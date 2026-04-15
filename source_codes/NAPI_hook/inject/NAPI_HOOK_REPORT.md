# NAPI Inline Hook 技术报告

## 项目目标

对 HarmonyOS (OpenHarmony 5.0) 模拟器上的定位应用 (`com.example.sys_verify`) 进行 NAPI 层 Hook，将 `NativeGetCurrentLocation` 函数替换为返回伪造坐标的自定义函数，实现**代码层面的替换**（非数据修改）。

## 最终结果

**成功。** 通过 inline hook 覆写 `NativeGetCurrentLocation` 函数入口，跳转到 mmap 区域中的 `fake_getLocation` 纯汇编函数，返回伪造坐标 (39.9087, 116.3975)。应用正常显示伪造位置，无崩溃。

---

## 目标应用架构

```
应用启动
  -> dlopen libentry.so
    -> __attribute__((constructor)) RegisterEntryModule()
      -> napi_module_register(&demoModule)
        -> Init(env, exports)
          -> napi_define_properties(env, exports, 3, desc[])
            -> desc[2].method = NativeGetCurrentLocation  <-- 映射发生在这里
    -> 库加载完成

用户点击 "Get Location"
  -> JS 引擎调用 NativeGetCurrentLocation(env, callback_info)
    -> napi_create_promise
    -> OH_Location_CreateRequestConfig
    -> OH_Location_StartLocating
    -> [异步回调] OnLocationUpdate -> CallJs
      -> OH_LocationInfo_GetBasicInfo (获取真实坐标)
      -> napi_create_object + napi_create_double + napi_set_named_property (构建返回对象)
      -> napi_resolve_deferred
```

### 关键 ELF 符号 (x86_64 libentry.so)

| 符号 | 偏移 | 类型 |
|------|------|------|
| `NativeGetCurrentLocation` | 0x2980 | FUNC LOCAL 540字节 |
| `RegisterEntryModule` | 0x2750 | FUNC (constructor) |
| `Init` | 0x2770 | FUNC |
| `demoModule` | 0x5a30 | OBJECT |
| `CallJs` | 0x2bc0 | FUNC LOCAL |
| `OnLocationUpdate` | 0x3040 | FUNC LOCAL |

---

## 尝试方案总览

| 方案 | 方法 | 结果 | 原因 |
|------|------|------|------|
| inject_v6 | PLT Hook `OH_LocationInfo_GetBasicInfo` | **成功** | 但只修改数据，非代码 |
| dlopen + libnapihook.so | GOT Hook + 重注册 | **失败** | linker namespace 隔离 |
| PLT Hook + napi_module_register | 强制重注册 | **失败** | NAPI 函数不能在非JS线程调用 |
| inject_napi (初版) | 覆写函数机器码 | **崩溃** | NAPI调用约定错误 |
| inject_napi (修复调用约定) | 修正 rdx->rsi | **崩溃** | 内存布局重叠 + RIP-relative偏移错误 |
| **inject_napi (最终版)** | **修复全部问题** | **成功** | |

---

## 方案一：inject_v6 -- PLT Hook（成功但不符合需求）

### 原理
修改 libentry.so 的 PLT stub，使 `OH_LocationInfo_GetBasicInfo` 的跨库调用先跳到我们的 trampoline，trampoline 调用原函数后覆写返回结构体中的 lat/lon 字段。

### 结果
- Hook 成功，进程存活
- 返回数据被成功篡改
- **但这是数据层面的修改**，原函数仍然执行

### 关键实现
- 在 ld-musl 的 code cave 中写入 trampoline shellcode
- trampoline 调用原函数后修改 Location_BasicInfo 结构体
- 用 mmap 分配新内存，将 trampoline 永久驻留

---

## 方案二：dlopen + libnapihook.so -- 失败

### 原理
通过 ptrace+dlopen 注入共享库 `libnapihook.so`，该库在 constructor 中：
1. Hook `napi_define_properties` 的 GOT
2. 调用 `napi_module_register(&demoModule)` 触发重注册
3. Hook 拦截重注册，替换 descriptor 中的 method 指针

### 失败原因
**HarmonyOS linker namespace 隔离**：应用进程的 dlopen 只能加载以下路径的共享库：
- `/system/lib64/`
- 应用自己的 bundle 目录 (`/data/storage/el1/bundle/libs/x86_64/`)

从 `/data/local/tmp/` 加载会返回 NULL。

### 解决尝试
- 直接写 `/system/lib64/`：权限不足
- 写入 bundle 目录：路径不确定且可能受 SELinux 限制

---

## 方案三：PLT Hook + 强制重注册 -- 失败

### 原理
在内存中直接执行（不依赖 dlopen）：
1. Hook `napi_define_properties` 的 PLT stub
2. 通过 shellcode 调用 `napi_module_register(&demoModule)` 触发重注册
3. Hook 拦截并替换 descriptor

### 失败原因
**NAPI 函数不能在非 JS 线程调用**。通过 ptrace 执行 shellcode 时，当前线程是 JS 主线程（被暂停），但此时 NAPI 的 napi_env 上下文不处于可安全调用状态。调用 `napi_module_register` 直接触发 SIGSEGV (signal 11)。

---

## 方案四：inject_napi -- Inline Hook（最终成功方案）

### 原理
**直接修改 `NativeGetCurrentLocation` 函数的机器码**，将函数开头覆盖为跳转指令，指向 mmap 区域中的 `fake_getLocation` 函数。

这是真正的代码修改：原函数的代码不再执行，完全由我们的函数接管。

### 实现流程
```
1. ptrace ATTACH 目标进程
2. 解析 libentry.so 的 ELF 头：
   - 找到 napi_define_properties 等 NAPI API 的 GOT 条目
   - 读取已解析的函数真实地址
3. 在 ld-musl 的 code cave 中执行 mmap shellcode：
   - syscall 9 (mmap): 分配 0x1000 字节 RWX 匿名内存
   - int3 断点返回控制
4. 在 mmap 区域写入 fake_getLocation 函数：
   - 数据区 [0x00-0x4F]: NAPI API 地址 + 伪造坐标
   - 代码区 [0x80]: fake_getLocation 汇编代码 (~0x17E bytes, 结束于 0x1FE)
   - 字符串区 [0x300]: "latitude", "longitude" 等 (与代码区隔离)
5. 覆写 NativeGetCurrentLocation 前 16 字节：
   - jmp [rip+0]; <fake_addr_8bytes>; nop nop
6. ptrace DETACH
```

### mmap 内存布局
```
偏移    内容                          大小
0x00    napi_create_promise 地址      8 bytes
0x08    napi_create_object 地址       8 bytes
0x10    napi_create_double 地址       8 bytes
0x18    napi_set_named_property 地址  8 bytes
0x20    napi_resolve_deferred 地址    8 bytes
0x28    fake_lat (39.9087)            8 bytes (double)
0x30    fake_lon (116.3975)           8 bytes (double)
0x38    fake_alt (50.0)               8 bytes (double)
0x40    fake_acc (5.0)                8 bytes (double)
0x48    fake_spd (0.0)                8 bytes (double)
0x50    (padding)
0x80    代码入口 (fake_getLocation)    ~0x17E bytes (结束于 0x1FE)
0x1FE   代码结束
0x200   (padding)
0x300   字符串常量                     ~50 bytes
```

### fake_getLocation 逻辑（纯 x86_64 汇编）
```
输入: rdi = napi_env, rsi = napi_callback_info
输出: rax = napi_value (Promise)

sub rsp, 0x58
mov [rsp+0x08], rdi          ; 保存 env

; napi_create_promise(env, &deferred, &promise)
; napi_create_object(env, &obj)

; 循环设置 5 个属性:
; napi_create_double(env, value_xmm0, &result)
; napi_set_named_property(env, obj, name, val)

; napi_resolve_deferred(env, deferred, obj)
; return promise

add rsp, 0x58
ret
```

---

## Bug 调试过程

### Bug 1: napi_create_double 调用约定错误

#### 崩溃现场
```
Signal: SIGSEGV(SEGV_MAPERR)@0x0000000000000002
#00 pc 0x5d092 libace_napi.z.so (napi_create_double+50)
#01 pc 0xd1 [Unknown]   <-- mmap 区域的 fake_getLocation 代码

r14 = 0x2                 <-- SEGV 访问地址 0x2
rsi = 0x504916f00700007f  <-- 垃圾值
rdi = 0x7f847d663690      <-- 看起来像有效的 napi_env
```

#### 根本原因

通过反汇编 libentry.so 中 `CallJs` 函数对 `napi_create_double` 的调用：

```asm
; 正确的调用方式 (编译器生成):
mov  rdi, [rbp - 256]      ; rdi = env
movsd xmm0, [rax]          ; xmm0 = double value
lea  rsi, [rbp - 184]      ; rsi = &result   <-- 注意: 是 rsi!
call napi_create_double
```

```asm
; inject_napi.c 中的错误调用:
mov  rdi, [rsp+0x08]       ; rdi = env
movsd xmm0, [rip+fake_lat] ; xmm0 = double value
lea  rdx, [rsp+0x48]       ; rdx = &result   <-- 错误! 应该是 rsi!
call napi_create_double
```

**分析**: `napi_create_double(napi_env env, double value, napi_value* result)` 签名中，`double value` 通过 `xmm0` 传递（System V AMD64 ABI 浮点调用约定），但它不占用整数寄存器位。因此后续整数参数 `napi_value* result` 走第二个整数寄存器 `rsi`，而非 `rdx`。这说明 **`xmm0` 传递浮点参数时不影响整数参数的编号顺序**。

从反汇编中确认的实际调用约定：

| 函数 | 实际参数 | 备注 |
|------|---------|------|
| `napi_create_promise(env, &deferred, &promise)` | rdi=env, rsi=&deferred, rdx=&promise | 标准 |
| `napi_create_object(env, &obj)` | rdi=env, rsi=&obj | 标准 |
| `napi_create_double(env, value, &result)` | **rdi=env, xmm0=value, rsi=&result** | **需注意!** |
| `napi_set_named_property(env, obj, name, val)` | rdi=env, rsi=obj, rdx=name, rcx=val | 标准 |
| `napi_resolve_deferred(env, deferred, obj)` | rdi=env, rsi=deferred, rdx=obj | 标准 |

#### 修复
在 `EMIT_DOUBLE_AND_SET` 宏中，将 `lea rdx, [rsp+0x48]` 改为 `lea rsi, [rsp+0x48]`：

```c
// 修复前 (错误):
buf[p++] = 0x48; buf[p++] = 0x8D; buf[p++] = 0x54; buf[p++] = 0x24; buf[p++] = 0x48; /* lea rdx, [rsp+0x48] */

// 修复后 (正确):
buf[p++] = 0x48; buf[p++] = 0x8D; buf[p++] = 0x74; buf[p++] = 0x24; buf[p++] = 0x48; /* lea rsi, [rsp+0x48] */
```

注意：调用 `napi_create_double` 后 `rsi` 被覆盖，后续的 `napi_set_named_property` 需要重新加载 `rsi=obj`。当前代码已有此处理（宏中在调用 `napi_set_named_property` 前重新 `mov rsi, [rsp+0x40]`）。

---

### Bug 2: 内存布局重叠 -- 代码区覆盖字符串区

#### 崩溃现场
```
Signal: SIGSEGV(SI_KERNEL)@0x0000000000000000
#00 pc 0x0000000000000180 [Unknown]    <-- rip = mmap_base + 0x180
#01 pc 0x0000000000006b8f [anon:native_heap:brk]

rax=0  rdi=env(有效)  rip = STR_ADDR 区域
```

#### 根本原因

初始内存布局设计中，代码区起始 `0x80`，字符串区起始 `0x180`，预留了 256 字节给代码。但实际生成的代码大小为 `0x17E` 字节（382 字节），代码从 `0x80` 延伸到 `0x1FE`。

```c
// 代码生成顺序:
size_t code_end = build_fake_func(hook_buf);  // 写入代码 0x80 ~ 0x1FE
build_strings(hook_buf);                       // 写入字符串 0x180 ~ 0x1AB <-- 覆盖了代码!
```

`build_strings()` 在 `build_fake_func()` **之后**调用，字符串 `"latitude\0longitude\0altitude\0accuracy\0speed\0"` 覆写了代码区 `0x180 ~ 0x1AB` 之间的指令字节。当代码执行到该区域时，CPU 实际在执行 ASCII 字符串，导致 `SIGSEGV`。

#### 修复

将 `STR_ADDR` 从 `0x180` 移到 `0x300`，确保与代码区（结束于 `0x1FE`）完全隔离：

```c
// 修复前:
#define STR_ADDR   0x180    // 与代码区重叠!

// 修复后:
#define STR_ADDR   0x300    // 在代码区之后
```

---

### Bug 3: RIP-relative 偏移计算错误

#### 根本原因

`rip_rel()` 辅助函数假设指令从 `instr_off` 开始、总长 7 字节：

```c
static int32_t rip_rel(size_t instr_off, size_t target_off)
{
    return (int32_t)((int64_t)target_off - (int64_t)(instr_off + 7));
}
```

这对 `emit_mov_rax_rip()` 是正确的（`48 8B 05` + `disp32` = 7 字节，调用时 `p` 指向指令起始）。

但在 `EMIT_DOUBLE_AND_SET` 宏中，`movsd xmm0` 和 `lea rdx` 在发出 prefix/opcode/ModR/M 字节**之后**才调用偏移计算，此时 `p` 已经指向 displacement 的起始位置，而非指令起始位置：

```c
// movsd xmm0, [rip+disp32]: F2 0F 10 05 <disp32>
//                                  ^-- p 在此处调用 rip_rel
buf[p++] = 0xF2; buf[p++] = 0x0F; buf[p++] = 0x10; buf[p++] = 0x05;
{ int32_t _r = rip_rel(p, data_off); memcpy(buf + p, &_r, 4); p += 4; }
// rip_rel(p, target) = target - (p + 7)  <-- 错误! 应该是 target - (p + 4)
```

**正确的计算**：当 `p` 指向 displacement 起始时，CPU 执行后 RIP = `p + 4`（displacement 占 4 字节），因此正确的 RIP-relative 偏移 = `target - (p + 4)`。

`rip_rel(p, target)` 计算的是 `target - (p + 7)`，比正确值多减了 3，导致引用地址偏移 3 字节。

#### 影响范围

两条指令受此 bug 影响：
1. `movsd xmm0, [rip+disp32]` -- 加载伪造坐标值，偏移错误导致加载垃圾 double
2. `lea rdx, [rip+disp32]` -- 加载属性名字符串地址，偏移错误导致指向错误位置

#### 修复

在宏中直接内联正确的偏移计算，不再使用 `rip_rel()`：

```c
// movsd xmm0: 正确的 RIP-relative 计算
{ int32_t _r = (int32_t)((int64_t)(data_off) - (int64_t)(p + 4));
  memcpy(buf + p, &_r, 4); p += 4; }

// lea rdx: 同理
{ int32_t _r = (int32_t)((int64_t)(name_off) - (int64_t)(p + 4));
  memcpy(buf + p, &_r, 4); p += 4; }
```

---

## 遇到的坑汇总

### 坑 1: HarmonyOS Linker Namespace 隔离
- **现象**: dlopen("/data/local/tmp/libnapihook.so") 返回 NULL
- **原因**: 应用进程受 linker namespace 限制，只能加载系统路径和 bundle 路径的库
- **解决**: 放弃 dlopen 方案，改用纯内存操作 (ptrace + mmap + /proc/pid/mem)

### 坑 2: NAPI 函数不能在非 JS 线程调用
- **现象**: 通过 ptrace shellcode 调用 napi_module_register 导致 SIGSEGV
- **原因**: NAPI 函数依赖 napi_env 上下文，该上下文与 JS 运行时绑定。ptrace 暂停线程后，JS 运行时处于不一致状态
- **解决**: 放弃"重注册"方案，改为 inline hook 直接修改函数代码

### 坑 3: MSYS 路径转换
- **现象**: `hdc file send /path/to/file` 路径被 Git Bash MSYS 层篡改
- **解决**: 命令前加 `MSYS_NO_PATHCONV=1`

### 坑 4: NAPI 调用约定差异 (napi_create_double)
- **现象**: fake_getLocation 中调用 napi_create_double 崩溃，SIGSEGV 访问 0x2
- **原因**: `double` 参数通过 `xmm0` 传递时不占整数寄存器位，后续整数参数仍从 `rsi` 开始编号。`napi_create_double(env, value, &result)` 实际为 `rdi=env, xmm0=value, rsi=&result`
- **解决**: 以目标库实际反汇编为准，将 `&result` 参数寄存器从 `rdx` 改为 `rsi`

### 坑 5: 代码区与字符串区内存布局重叠
- **现象**: 修复调用约定后仍然崩溃，rip 落在 STR_ADDR (0x180) 处
- **原因**: 生成的代码 382 字节超过了预留的 256 字节空间，`build_strings()` 覆盖了代码尾部
- **解决**: 将 `STR_ADDR` 从 `0x180` 移到 `0x300`，与代码区完全隔离

### 坑 6: RIP-relative 偏移计算不一致
- **现象**: 即使内存布局修复后，`movsd xmm0` 和 `lea rdx` 引用的地址仍有偏移
- **原因**: `rip_rel()` 辅助函数假设调用时 `p` 为指令起始位置且指令总长 7 字节。但 `movsd xmm0` 和 `lea rdx` 在发出 prefix/opcode 字节后才调用，`p` 已指向 displacement 起始位置
- **解决**: 对这两条指令使用内联计算 `target - (p + 4)` 而非 `rip_rel(p, target)`

### 坑 7: Stack Alignment
- System V ABI 要求在执行 `call` 指令时 `rsp` 必须是 16 字节对齐
- fake_getLocation 通过 `sub rsp, 0x58` 分配栈帧
- inline hook 使用 `jmp`（非 `call`），所以函数入口 rsp = 16n - 8（来自原始 `call` push 的返回地址）
- `sub rsp, 0x58` 后：rsp = 16n - 8 - 0x58 = 16n - 96 = 16(n-6)，对齐正确
- 函数内无额外 push/pop，每次 `call` 前 rsp 保持 16 字节对齐

---

## 文件清单

| 文件 | 状态 | 说明 |
|------|------|------|
| `inject/inject_napi.c` | **可用** | Inline Hook 注入器（最终版，已修复全部 bug） |
| `inject/inject_v6.c` | 可用 | PLT Hook，数据层修改 |
| `inject/libnapihook.c` | 不可用 | dlopen 方案，因 linker namespace 失败 |
| `inject/inject_dlopen.c` | 不可用 | dlopen 注入器 |
| `inject/inject.c` | 参考 | 原始 shellcode 注入 + dlopen |
| `inject/hook.c` | 参考 | GOT Hook 共享库 |
| `entry/src/main/cpp/napi_init.cpp` | 目标 | 被 Hook 的 NAPI 模块源码 |

---

## 关键技术要点总结

### 1. inline hook 流程
1. **ptrace attach** 暂停目标线程
2. **ELF GOT 解析** 获取 NAPI API 函数的真实地址（读取已 resolve 的 GOT 条目）
3. **mmap 分配 RWX 内存**：在 ld-musl 的 code cave 中执行 syscall shellcode 分配匿名内存
4. **写入 fake 函数**：在 mmap 区域构造完整的 NAPI 调用逻辑（纯机器码）
5. **覆写目标函数入口**：`jmp [rip+0]; <addr>` 16 字节 patch
6. **ptrace detach** 恢复目标线程

### 2. 纯汇编实现 NAPI 调用的注意事项
- **必须反汇编验证调用约定**：不能依赖 NAPI 标准文档，以目标平台编译器实际输出为准
- **浮点参数特殊处理**：`xmm0` 传递 `double` 时不影响整数参数编号顺序，`napi_create_double(env, double, napi_value*)` 实际为 `(rdi, xmm0, rsi)` 而非 `(rdi, xmm0, rdx)`
- **寄存器保存/恢复**：NAPI 函数调用会破坏 `rsi` 等寄存器，每次调用前需重新设置参数
- **内存布局隔离**：代码区、数据区、字符串区必须明确分隔，防止写入顺序导致覆盖
- **RIP-relative 偏移**：`rip_rel()` 辅助函数仅在 `p` 指向指令起始时正确，对已发出 prefix/opcode 后的情况需内联计算

### 3. HarmonyOS 特有限制
- **Linker namespace 隔离**：应用进程无法通过 dlopen 加载 `/data/local/tmp/` 下的库
- **NAPI 线程安全**：NAPI 函数不能在 ptrace 暂停的非 JS 上下文中调用
- **获取 crash log**：`/data/log/faultlog/faultlogger/cppcrash-<pkg>-<uid>-<timestamp>` 包含详细崩溃信息

---

## 使用指南：从编译到注入

### 前置条件

- DevEco Studio 已安装，SDK 路径默认在 `C:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony`
- 目标应用已安装并在模拟器上运行
- Git Bash 或类似终端（Windows 下 `hdc` 路径自动转换需用 `MSYS_NO_PATHCONV=1` 绕过）
- `inject_napi.c` 位于 `inject/` 目录

### 修改伪造坐标（可选）

编辑 `inject/inject_napi.c` 顶部的全局变量：

```c
static double g_fake_lat = 39.9087;   // 伪造纬度
static double g_fake_lon = 116.3975;  // 伪造经度
static double g_fake_alt = 50.0;      // 伪造海拔
static double g_fake_acc = 5.0;       // 伪造精度
static double g_fake_spd = 0.0;       // 伪造速度
```

如果目标应用的 `NativeGetCurrentLocation` 偏移不是 `0x2980`（例如 libentry.so 重新编译后），需同步修改：

```c
#define NATIVE_GET_LOCATION_OFFSET 0x2980
```

### 第一步：编译

```bash
# 设置编译工具链路径
CLANG="C:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/native/llvm/bin/clang.exe"
SYSROOT="C:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/native/sysroot"

# 编译 (目标平台 x86_64 OpenHarmony)
"$CLANG" --target=x86_64-linux-ohos -O2 --sysroot="$SYSROOT" \
    -o inject/inject_napi inject/inject_napi.c -ldl
```

编译成功后生成 `inject/inject_napi`（ELF x86_64 可执行文件）。

### 第二步：推送到模拟器

```bash
# 从 inject/ 目录推送（MSYS_NO_PATHCONV=1 防止路径被 Git Bash 篡改）
cd inject && MSYS_NO_PATHCONV=1 hdc file send inject_napi /data/local/tmp/inject_napi
```

输出应为 `FileTransfer finish`。

### 第三步：启动目标应用并获取 PID

```bash
# 如果应用未运行，先启动
hdc shell "aa start -a EntryAbility -b com.example.sys_verify"

# 获取 PID
hdc shell "ps -ef | grep sys_verify | grep -v grep"
```

输出示例：
```
20020039     23780   127 176406837 21:08:39 ? ... com.example.sys_verify
```

其中 `23780` 就是 PID。

### 第四步：注入

```bash
# 赋予执行权限并注入
MSYS_NO_PATHCONV=1 hdc shell "chmod +x /data/local/tmp/inject_napi && /data/local/tmp/inject_napi <PID>"
```

将 `<PID>` 替换为上一步获取的实际值，例如：

```bash
MSYS_NO_PATHCONV=1 hdc shell "chmod +x /data/local/tmp/inject_napi && /data/local/tmp/inject_napi 23780"
```

成功输出示例：
```
[INJECT] === NAPI Inline Hook ===
[INJECT] PID=23780 fake=(39.908700, 116.397500)
[INJECT] Attached
[INJECT] libentry.so base=0x7f8464380000
[INJECT] napi_create_promise      = 0x7f847c2a6350
[INJECT] napi_create_object       = 0x7f847c29ca80
[INJECT] napi_create_double       = 0x7f847c29d060
[INJECT] napi_set_named_property  = 0x7f847c29eef0
[INJECT] napi_resolve_deferred    = 0x7f847c2a6460
[INJECT] NativeGetCurrentLocation = 0x7f8464382980 (base+0x2980)
[INJECT] mmap=0x7f8475317000
[INJECT] fake_getLocation at 0x7f8475317080
[INJECT] === NAPI Inline Hook done! ===
[INJECT] Location will be: lat=39.908700 lon=116.397500
```

关键检查点：
- 所有 5 个 NAPI API 地址均非零
- `mmap` 地址非零且非 `0xFFFFFFFF`
- `Verify patch` 字节以 `ff 25` 开头

### 第五步：触发并验证

在模拟器上点击应用界面的 **"Get Location"** 按钮。

如果成功，应用显示伪造坐标 (39.9087, 116.3975) 而非真实位置。

如果闪退，查看 crash log：
```bash
# 查看最新的崩溃日志
hdc shell "ls -lt /data/log/faultlog/faultlogger/ | head -3"
hdc shell "head -80 /data/log/faultlog/faultlogger/<最新文件名>"
```

### 一键脚本

Windows 环境下直接在 `inject/` 目录双击或命令行运行 `inject.bat`：

```
cd inject
inject.bat
```

脚本自动完成编译 -> 推送 -> 查找 PID -> 注入全流程。如果目标应用未运行，会自动启动后重试。

修改伪造坐标只需编辑 `inject_napi.c` 顶部的 `g_fake_lat` / `g_fake_lon` 等变量，然后重新运行 `inject.bat`。

### 注意事项

- 每次应用重新启动后需要重新注入（inline patch 在内存中，进程退出后失效）
- 注入前应用必须已经完成初始化（libentry.so 已加载）
- 如果 libentry.so 重新编译，`NativeGetCurrentLocation` 的偏移可能变化，需用 `llvm-objdump` 或 `llvm-readelf` 重新确认
