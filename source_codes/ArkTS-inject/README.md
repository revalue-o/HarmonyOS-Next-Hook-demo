# ArkTS 层 Hook：CDP Inspector 字节码注入

## 概述

本项目在 HarmonyOS Next (x86_64 模拟器) 上通过 **CDP (Chrome DevTools Protocol) + Ark Inspector** 注入 `.abc` 字节码，在 ArkTS 层 monkey-patch `globalThis.requireNapi`，拦截 `geoLocationManager` 模块加载，替换 `getCurrentLocation` 为返回伪造坐标的函数。

这是三层 Hook 中最复杂的一层。与 Native 层 (PLT Hook) 和 NAPI 层 (Inline Hook) 的纯内存操作不同，ArkTS 层 Hook 需要理解 Ark 引擎的调试架构，利用 CDP 调试协议注入自定义字节码。

## 技术原理

### 为什么 Hook requireNapi

NAPI 导出对象的属性是 frozen + non-configurable 的：
```javascript
gm.getCurrentLocation = fn     // ❌ "Cannot assign to read only property"
Object.defineProperty(gm, ...)  // ❌ "Cannot define property"
new Proxy(gm, { get: ... })    // ❌ APP 持有原始引用，不走 Proxy
```

但 `globalThis.requireNapi` 是全局函数，可以替换。`import` 语句底层通过它加载模块：
```
import { geoLocationManager } from '@kit.LocationKit'
         ↓ 底层调用
requireNapi('geoLocationManager')  ← 在此拦截
         ↓ 返回包含伪造 getCurrentLocation 的对象
```

Hook 的核心逻辑：不修改 NAPI 对象本身，而是拦截模块加载过程。当 import 语句调用 `requireNapi` 时，返回一个包含伪造方法的对象（浅拷贝 + 替换 `getCurrentLocation`）。其他模块 (AbilityContext、WindowStage、abilityAccessCtrl 等) 正常透传。

### Ark 引擎调试架构

注入过程涉及以下系统库：

```
┌───────────────────────────────────────────────────────┐
│  libark_tooling.so                                    │
│    CDP 协议处理器                                      │
│    导出: InitializeDebugger, OnMessage,               │
│          WaitForDebugger, ProcessMessage, ...         │
├───────────────────────────────────────────────────────┤
│  libark_inspector.z.so                                │
│    Inspector 适配层                                    │
│    导出: StartDebugForSocketpair(pid, socketfd)       │
│    全局变量: g_handle, g_initializeDebugger 等         │
│    通过 emutls 存储 TLS 变量                           │
├───────────────────────────────────────────────────────┤
│  libark_connect_inspector.z.so                        │
│    WebSocket 传输层                                    │
│    实现: WsServer + pthread_create → WebSocket 服务器  │
├───────────────────────────────────────────────────────┤
│  libark_jsruntime.so                                  │
│    Ark JS 运行时                                      │
│    提供: EcmaVM, GetEcmaVM(tid)                       │
│    调试 API: EvaluateViaFuncCall, SetModuleValue 等   │
└───────────────────────────────────────────────────────┘
```

### CDP 协议支持情况

Ark 引擎实现了 CDP 的子集 (Dynamic 分发器)：

| CDP 方法 | 支持情况 | 说明 |
|----------|---------|------|
| `Runtime.enable` | ✅ | 必须先启用 |
| `Debugger.enable` | ✅ | 必须先启用 |
| `Debugger.pause` | ✅ | 在下一个语句暂停 |
| `Debugger.resume` | ✅ | 恢复执行 |
| `Debugger.disable` | ✅ | 关闭调试器 |
| `Runtime.runIfWaitingForDebugger` | ✅ | 通知 VM 继续启动 |
| `Runtime.evaluate` | ❌ | Dynamic 分发器不支持 |
| `Debugger.evaluateOnCallFrame` | ❌ | 返回 undefined |
| `Debugger.callFunctionOn` | ✅ | **唯一可用的代码注入通道** |

### callFunctionOn 只接受 .abc 字节码

`callFunctionOn` 的 `functionDeclaration` 参数不接受 JS 源码，必须是 **base64 编码的 .abc (Ark Bytecode)** 文件：

```
JS 源码 (.js) → es2abc 编译 → .abc 字节码 → base64 编码 → 嵌入 CDP JSON
```

## 完整注入流程

### 流程总览

```
┌─────────────────────────────────────────────────────────────────┐
│ Phase 0: 准备                                                    │
│   aa start -D -a EntryAbility -b com.example.sys_verify         │
│   (必须用 -D 调试模式启动，否则 Debugger.pause 不会触发)           │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│ Step 1: ptrace ATTACH 主线程                                     │
│   获取寄存器快照 orig_regs                                       │
│   搜索 gadget: "syscall; ret" 和 "call rax"                     │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│ Step 2: 远程内存分配 (mmap)                                      │
│   通过 syscall gadget 执行 mmap(NULL, 0x4000, RW, ANON|PRIV)    │
│   获得 4 页 (16KB) 匿名内存:                                     │
│     +0x0000: 代码页 (shellcode, 后 mprotect→RX)                  │
│     +0x1000: 保留                                               │
│     +0x2000: data_buf (CDP 写入缓冲, RW)                        │
│     +0x3000: rd_buf (CDP 读取缓冲, RW)                          │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│ Step 3: 远程 socketpair                                          │
│   syscall gadget 执行 socketpair(AF_UNIX, SOCK_STREAM)          │
│   → sv[0] (给 Inspector 服务器), sv[1] (给注入器)               │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│ Step 4: 解析符号 + 预设全局变量                                   │
│   定位 libark_inspector.z.so 和 libark_tooling.so               │
│   调用 GetEcmaVM(pid) 获取 VM 指针                              │
│   将 libark_tooling.so 中 6 个函数地址写入 libark_inspector      │
│   的全局变量 (绕过 dlopen/dlsym)                                 │
│   设置 g_hasArkFuncsInited = 1                                  │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│ Step 5: 执行 Shellcode                                          │
│   mprotect 代码页 → RX                                          │
│   Shellcode (60 字节):                                          │
│     1. __emutls_get_address(g_handle) → 设置 g_handle=1         │
│     2. StartDebugForSocketpair(pid, sv[0])                      │
│   → Inspector WebSocket 服务器在 sv[0] 上启动                    │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│ Step 6: WebSocket 握手                                           │
│   向 sv[1] 发送 HTTP Upgrade 请求                               │
│   收到 101 Switching Protocols                                   │
│   设置 sv[1] 为 O_NONBLOCK                                      │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│ Phase 1: CDP 域启用 + 暂停                                       │
│   send: Runtime.enable                                          │
│   send: Debugger.enable                                         │
│   send: Debugger.pause                                          │
│   send: Runtime.runIfWaitingForDebugger                         │
│   detach → 等待 5 秒 → reattach                                 │
│   收到: Debugger.paused (reason="Break on start")               │
│   ← 第一次暂停: EntryAbility.ts 加载前                          │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│ Phase 4: Resume → 第二次 Pause                                   │
│   send: Debugger.resume                                         │
│   detach → 等待 3 秒 → reattach                                 │
│   drain 所有 WS 响应，找到第二次 Debugger.paused                  │
│   收到: Debugger.paused (lineNumber=5, reason="other")          │
│   ← 第二次暂停: EntryAbility.ts 第 5 行                         │
│   此时 onWindowStageCreate 已执行到 loadContent 前               │
│   Index.ets 和 LocationUtil.ets 尚未加载                        │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│ Phase 5b: requireNapi Hook 注入 ← 核心攻击步骤                   │
│   callFunctionOn(monkey_patch_scope.abc base64)                 │
│   .abc 执行:                                                    │
│     1. 保存原始 globalThis.requireNapi                           │
│     2. 替换为自定义函数                                          │
│     3. 当 mod === "geoLocationManager" 时返回 hook 对象          │
│     4. hook 对象的 getCurrentLocation 调用原函数后篡改坐标       │
│   → 返回 {"type":"undefined"} (执行成功)                        │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│ Phase 6: Final Resume                                           │
│   send: Debugger.resume                                         │
│   detach → 等待 → reattach                                      │
│   APP 继续执行:                                                  │
│     loadContent('pages/Index')                                  │
│     → Index.ets 加载                                            │
│     → import { geoLocationManager } from '@kit.LocationKit'     │
│     → 底层调用 requireNapi('geoLocationManager')                │
│     → 被 Hook 拦截! 返回包含伪造 getCurrentLocation 的对象       │
│     → APP 正常显示 UI                                           │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│ Phase 7: 清理调试器                                              │
│   send: Debugger.disable                                        │
│   send: Runtime.disable                                         │
│   → 防止调试器继续拦截 JS 执行 (否则 APP UI 会卡住)             │
│   ptrace DETACH                                                 │
│   APP 正常运行，位置已伪造                                       │
└─────────────────────────────────────────────────────────────────┘
```

### 注入时序分析

第二次 Pause 发生在 `EntryAbility.ts:5`，即 `onWindowStageCreate` 回调内部：

```
EntryAbility.ts:
  0: func_main_0() {                           ← 第一次 Pause ("Break on start")
  1:   ...
  5:   windowStage.loadContent('pages/Index')  ← 第二次 Pause (lineNumber:5)
  6:   ...
  }
```

在第二次 Pause 时注入 requireNapi Hook：
- `EntryAbility.ts` 模块已加载 ✅
- `windowStage.loadContent('pages/Index')` **尚未执行** ✅ (被 Pause 阻断)
- `Index.ets` 和 `LocationUtil.ets` **尚未加载** ✅
- 这些模块的 `import { geoLocationManager } from '@kit.LocationKit'` **尚未执行** ✅

Resume 后，APP 加载 Index.ets，import 语句触发 `requireNapi('geoLocationManager')`，被注入的 Hook 拦截。

## 关键技术细节

### 1. 绕过 dlopen/dlsym 限制

`StartDebugForSocketpair` 内部调用 `InitializeDebuggerForSocketpair(vm)`，后者需要通过 `dlopen` 加载 `libark_tooling.so` 并 `dlsym` 解析 6 个函数指针。HarmonyOS 沙箱环境限制 `dlopen` 只能加载系统路径和 bundle 路径的库。

解决方案：直接将 `libark_tooling.so` 的函数地址写入 `libark_inspector.z.so` 的全局变量：

| 全局变量 (VA 偏移) | 目的 | 来源 |
|---------------------|------|------|
| `g_initializeDebugger` (0x15db8) | 初始化调试器 | libark_tooling.so: InitializeDebugger (0x9a7e0) |
| `g_uninitializeDebugger` (0x15dc8) | 反初始化 | UninitializeDebugger (0x9ac20) |
| `g_waitForDebugger` (0x15dc0) | 等待连接 | WaitForDebugger (0x9aef0) |
| `g_onMessage` (0x15d68) | 消息处理 | OnMessage (0x9b070) |
| `g_getDispatchStatus` (0x15d70) | 调度状态 | GetDispatchStatus (0x9b370) |
| `g_processMessage` (0x15dd8) | 处理消息 | ProcessMessage (0x9b1f0) |
| `g_hasArkFuncsInited` (0x15dd0) | 标志位 | 设为 1 跳过 dlsym |

### 2. 绕过 g_handle 的 TLS (emutls)

`g_handle` 是通过 GCC `__thread` 声明的 TLS 变量，存储在 emutls 中。不能直接写内存，需要调用 `__emutls_get_address` 获取 TLS 地址后再写。这是 Shellcode 的第一个任务：

```asm
; Shellcode 片段 (x86_64)
mov rdi, <emutls_control_g_handle>    ; 0x15be0 + base
mov rax, <__emutls_get_address@plt>   ; 0x13280 + base
call rax                               ; rax = &g_handle (TLS slot)
mov qword [rax], 1                     ; g_handle = (void*)1 (skip dlopen)
```

### 3. RWX 不可用 → mmap(RW) + mprotect(RX)

HarmonyOS Next 使用 seccomp 禁止同时设置 RW+RX 权限。因此先分配 RW 内存写入 shellcode，再 mprotect 改为 RX：

```c
mmap(NULL, 0x4000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
// 写入 shellcode 后...
mprotect(mmap_addr, 0x1000, PROT_READ|PROT_EXEC);
```

### 4. syscall restart 防护

目标线程在 `futex` 中等待，通过 `PTRACE_SETREGS` 修改寄存器后执行 syscall 时，必须设置 `orig_rax = -1` 防止内核在 syscall 返回时重启被中断的系统调用：

```c
regs.orig_rax = (uint64_t)-1;  // 关键: 防止 syscall restart
ptrace(PTRACE_SETREGS, pid, NULL, &regs);
```

### 5. detach/reattach 机制

CDP 命令需要主线程运行才能处理 (Inspector 通过 postTask 向 JS 线程投递任务)。但 ptrace attach 时线程被冻结。因此每次 CDP 命令都需要一个 detach/reattach 周期：

```
发送 CDP 命令 → ptrace DETACH → 主线程运行处理 CDP → 等待 → ptrace RE-ATTACH → 读取结果
```

### 6. ELF 符号解析

注入器通过远程读取 ELF header → PT_DYNAMIC → DT_STRTAB/DT_SYMTAB → 遍历符号表匹配名称。对于 libark_tooling.so 这样的大符号表 (index > ~1000)，GNU hash 表解析有 bug，因此使用通过静态分析 (llvm-objdump) 获取的硬编码 VA 偏移作为 fallback。

### 7. .abc 源文件名敏感性

`callFunctionOn` 的 Dynamic 分发器内部调用 `GenerateFuncFromBuffer`，该函数检查 .abc 中嵌入的源文件路径。编译 .abc 时源文件名**必须**为 `monkey_patch_scope.js`，否则执行失败。

### 8. CDP 消息大小限制

原始缓冲区只有一页 (4096 字节)，较大的 .abc base64 编码后超过此限制。解决方案是扩展 mmap 到 4 页，将 `data_buf` (CDP 写入缓冲) 放在 +0x2000，`rd_buf` (CDP 读取缓冲) 放在 +0x3000。

### 9. Debugger 清理

注入完成后，必须发送 `Debugger.disable` 和 `Runtime.disable`，否则 Inspector 的调试钩子仍然拦截 JS 执行，导致 APP UI 卡在启动画面。

## 目录结构

```
ArkTS-inject/
├── AppScope/                  # 应用级配置和资源
├── entry/                     # 主模块
│   ├── src/main/
│   │   ├── ets/
│   │   │   ├── pages/Index.ets           # 主界面
│   │   │   └── utils/
│   │   │       ├── LocationUtil.ets      # ArkTS 层位置服务
│   │   │       └── NativeLocationUtil.ets # Native 层位置服务
├── inject/                    # Hook 注入工具
│   ├── inject_debugger.c      # CDP Inspector 注入器 (当前版本)
│   ├── inject_debugger        # 编译后的二进制
│   ├── monkey_patch_scope.js  # Monkey-patch 源码 (文件名不可改)
│   ├── monkey_patch_scope.abc # 编译后的 .abc 字节码 (API 12)
│   ├── libark_inspector.z.so  # 从设备提取 (分析用)
│   ├── libark_tooling.so      # 从设备提取 (分析用)
│   ├── libark_connect_inspector.z.so
│   └── ARKTS_HOOK.md          # 简洁技术文档
├── build-profile.json5
└── oh-package.json5
```

## 环境要求

- HarmonyOS Next x86_64 模拟器 (已 root)
- DevEco Studio + HarmonyOS SDK
- 工具链：`sdk/default/openharmony/native/llvm/bin/clang.exe`
- es2abc 编译器（可从gitee下载）：`sdk/default/openharmony/ets/build-tools/ets-loader/bin/ark/build-win/bin/es2abc.exe`
- hdc (HarmonyOS Device Connector)
- Python (用于 base64 编码 .abc 嵌入 C 源码)

Root 模拟器参考：https://wuxianlin.com/2024/10/27/root-harmonyos-next-emultor/
**请注意，该模拟器使用旧版API，这会影响ArkTS Hook的.abc字节码的编译命令**

## 安装与使用

### 1. 编译目标应用

用 DevEco Studio 打开 `ArkTS-inject` 目录，编译并安装到模拟器。

### 2. (可选) 修改伪造坐标并编译 .abc 字节码

如需修改伪造坐标，编辑 `inject/monkey_patch_scope.js`：
```javascript
loc.latitude = 39.9087;
loc.longitude = 116.3977;
```

然后重新编译 .abc 字节码：

```bash
ES2ABC="C:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/ets/build-tools/ets-loader/bin/ark/build-win/bin/es2abc.exe"

"$ES2ABC" --module --target-api-version 12 --output monkey_patch_scope.abc monkey_patch_scope.js
```

### 3. base64 编码 .abc 并嵌入 inject_debugger.c

将编译好的 .abc 文件 base64 编码，替换 `inject_debugger.c` 中的 `abc_b64_v2` 常量：

```python
import base64
b64 = base64.b64encode(open('monkey_patch_scope.abc','rb').read()).decode()
print(f'const char abc_b64_v2[] = "{b64}";')
```

将输出的 base64 字符串替换 `inject_debugger.c` 中 `abc_b64_v2` 数组的内容。

### 4. 编译注入工具

```bash
CLANG="C:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/native/llvm/bin/clang.exe"
SYSROOT="C:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/native/sysroot"

"$CLANG" --target=x86_64-linux-ohos -O2 --sysroot="$SYSROOT" -o inject_debugger inject_debugger.c
```

### 5. 推送到设备

```bash
hdc file send inject_debugger /data/local/tmp/inject_debugger
hdc shell "chmod +x /data/local/tmp/inject_debugger"
```

### 6. 以调试模式启动应用

```bash
hdc shell aa force-stop com.example.sys_verify
hdc shell "aa start -D -a EntryAbility -b com.example.sys_verify"
```

**必须使用 `-D` 参数**。不带 `-D` 时，模块在 Inspector 连接前加载完毕，`Debugger.pause` 永远不触发。

### 7. 获取 PID

```bash
hdc shell "ps -ef | grep sys_verify | grep -v grep | awk '{print \$2}'"
```

### 8. 执行注入

```bash
hdc shell "/data/local/tmp/inject_debugger <PID>"
```

### 9. 验证

在应用中点击 "获取位置 (ArkTS)" 按钮，应显示伪造坐标 `lat=39.908700, lon=116.397700`。

可通过 hilog 确认注入是否成功：
```bash
hdc shell "hilog | grep MP_"
```

预期日志输出：
```
MP_H: origRN saved
MP_H: requireNapi hooked successfully!
MP_H: requireNapi called with: application.AbilityContext    ← 透传
MP_H: requireNapi called with: application.WindowStage       ← 透传
MP_H: requireNapi called with: abilityAccessCtrl             ← 透传
MP_H: requireNapi called with: geoLocationManager            ← 拦截!
MP_H: intercepted geoLocationManager!
MP_H: copied property: getCurrentLocation
MP_H: ...
MP_H: hooked object created!
```

点击按钮后追加：
```
MP_H: getCurrentLocation called!
MP_H: location patched!
```

### 预期注入器输出

```
[DBG-INJECT] Phase 5b 返回: {"id":7,"result":{"result":{"type":"undefined"}}}
[DBG-INJECT] Phase 7: Debugger.disable → {"id":9,"result":{}}
[DBG-INJECT] Phase 7: Runtime.disable → {"id":10,"result":{}}
[DBG-INJECT] === Done! ===
OK
```

## .abc Hook 源码说明

`monkey_patch_scope.js` 的核心逻辑：

```javascript
var origRN = globalThis.requireNapi;               // 保存原始函数
globalThis.requireNapi = function(mod) {            // 替换为自定义函数
    var r = origRN(mod);                            // 调用原始函数获取真实模块
    if (mod === "geoLocationManager" && r && typeof r.getCurrentLocation === "function") {
        var origGCL = r.getCurrentLocation;
        var hooked = {};                            // 创建浅拷贝对象（绕过 frozen）
        Object.getOwnPropertyNames(r).forEach(function(k) {
            try { hooked[k] = r[k]; } catch(e) {}  // 复制所有属性
        });
        hooked.getCurrentLocation = function(req) {
            return origGCL.call(r, req).then(function(loc) {
                if (loc) {
                    loc.latitude = 39.9087;         // 伪造坐标
                    loc.longitude = 116.3977;
                }
                return loc;
            });
        };
        return hooked;                              // 返回 hook 对象
    }
    return r;                                       // 其他模块正常透传
};
```

## 局限性

1. 必须以调试模式 (`aa start -D`) 启动应用
2. 需要 root 权限 (ptrace + /proc/pid/mem)
3. 仅在 x86_64 模拟器上测试通过
4. 应用重启后需重新注入
5. `libark_inspector.z.so` / `libark_tooling.so` 的 VA 偏移 (如 0x15db8, 0x9a7e0 等) 可能随系统版本变化，需用 `llvm-objdump` 重新确认
6. GNU hash 表对大符号表的解析有 bug，部分符号需硬编码偏移
