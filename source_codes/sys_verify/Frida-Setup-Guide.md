# HarmonyOS Next 模拟器 Frida Hook 环境

## 1. 环境信息

| 项目 | 值 |
|------|-----|
| 模拟器系统 | HarmonyOS Next (OHOS), Linux 内核 5.10.209 |
| 模拟器架构 | x86_64 |
| C 运行时 | musl libc (非 glibc) |
| Root | 已 root，shell 默认 root 用户 |
| 设备连接 | hdc（类似 adb），连接地址 127.0.0.1:5555 |
| PC 端 Frida 版本 | 17.5.2 |
| frida-server 版本 | 17.5.2-linux-x86_64-musl（必须用 musl 版本） |

**关键约束：** HarmonyOS Next 使用 musl libc，frida-server 必须使用 musl 编译版本，glibc 版本会报 "No such file or directory" 或 "Not a valid dynamic program"。

## 2. frida-server 部署

### 文件位置
- 设备路径：`/data/local/tmp/frida-server`
- 启动脚本：`/data/local/tmp/start_frida.sh`
- 日志文件：`/data/local/tmp/frida.log`

### 启动命令
```bash
# 方式 1：通过启动脚本
hdc shell "sh /data/local/tmp/start_frida.sh"

# 方式 2：直接运行（需要用 nohup 放后台，否则会随 shell 退出而终止）
hdc shell "nohup /data/local/tmp/frida-server -D > /dev/null 2>&1 &"
```

### 检查是否运行
```bash
hdc shell "ps -ef | grep frida-server"
```

### 停止
```bash
hdc shell "killall frida-server"
```

## 3. 端口转发

```bash
# 设置端口转发（frida 默认端口 27042）
hdc fport tcp:27042 tcp:27042

# 查看已有转发
hdc fport ls

# 删除转发
hdc fport rm tcp:27042 tcp:27042
```

## 4. Frida 连接

所有 frida 命令通过 `-H 127.0.0.1:27042` 连接模拟器：

```bash
# 列出所有进程
frida-ps -H 127.0.0.1:27042

# 列出已安装的应用
frida-ps -H 127.0.0.1:27042 -ai

# 附加到运行中的进程
frida -H 127.0.0.1:27042 -n <包名>

# 附加并加载脚本
frida -H 127.0.0.1:27042 -n <包名> -l hook.js

# Spawn 模式（重启应用并 hook）
frida -H 127.0.0.1:27042 -f <包名> -l hook.js --no-pause
```

## 5. Native Hook 脚本模板

### 5.1 监控函数调用（Interceptor.attach）

```javascript
// hook_exports.js
// Hook 指定 so 库中导出的 native 函数

var moduleName = "libnative.so";   // 目标 so 文件名
var funcName = "my_native_func";   // 目标函数名

function doHook() {
    var mod = Process.findModuleByName(moduleName);
    if (!mod) {
        console.log("[-] Module not loaded yet: " + moduleName);
        return;
    }
    console.log("[+] Module found: " + mod.name + " base=" + mod.base);

    var addr = mod.findExportByName(funcName);
    if (!addr) {
        console.log("[-] Export not found: " + funcName);
        // 列出所有导出函数帮助排查
        mod.enumerateExports().forEach(function(e) {
            console.log("    " + e.type + " " + e.name + " @ " + e.address);
        });
        return;
    }
    console.log("[+] Found " + funcName + " at " + addr);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log("[*] " + funcName + " called");
            // 读取参数（根据实际函数签名）
            // args[0] - 第一个参数
            // args[1] - 第二个参数
            // ...

            // 读取字符串参数示例：
            // console.log("    arg0 (string): " + args[0].readUtf8String());

            // 修改参数示例：
            // args[0] = ptr(0x1234);
        },
        onLeave: function(retval) {
            console.log("[*] " + funcName + " returning: " + retval);
            // 修改返回值示例：
            // retval.replace(42);
        }
    });
}

// 如果 so 已加载直接 hook，否则等待加载
var mod = Process.findModuleByName(moduleName);
if (mod) {
    doHook();
} else {
    console.log("[*] Waiting for " + moduleName + " to load...");
    // 用 dlopen hook 等待 so 加载
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function(args) {
            this.path = args[0].readUtf8String();
        },
        onLeave: function(retval) {
            if (this.path && this.path.indexOf(moduleName) !== -1) {
                console.log("[*] " + moduleName + " loaded via dlopen");
                doHook();
            }
        }
    });
}
```

### 5.2 替换函数实现（Interceptor.replace）

```javascript
var addr = Module.findExportByName("libnative.so", "check_license");
if (addr) {
    Interceptor.replace(addr, new NativeCallback(function() {
        console.log("[*] check_license() replaced -> returning 1 (licensed)");
        return 1;
    }, 'int', []));
}
```

### 5.3 Hook 系统/libc 函数

```javascript
// Hook open 系统调用，监控文件访问
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        console.log("[open] " + path);
    }
});

// Hook connect，监控网络连接
Interceptor.attach(Module.findExportByName(null, "connect"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var addr = args[1];
        var addrLen = args[2].toInt32();
        console.log("[connect] fd=" + fd);
    }
});
```

## 6. 常用辅助代码片段

```javascript
// 枚举进程已加载的所有模块（so 库）
Process.enumerateModules().forEach(function(m) {
    console.log(m.name + " @ " + m.base + " size=" + m.size);
});

// 枚举指定模块的所有导出函数
Module.enumerateExports("libnative.so").forEach(function(e) {
    console.log(e.type + " " + e.name + " @ " + e.address);
});

// 枚举指定模块的所有导入函数
Module.enumerateImports("libnative.so").forEach(function(e) {
    console.log(e.name + " from " + e.module);
});

// 在指定地址设置断点式监控
Interceptor.attach(ptr("0x7f12345678"), {
    onEnter: function(args) {
        console.log("Hit 0x7f12345678");
        console.log("Backtrace:\n" +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join("\n"));
    }
});
```

## 7. 注意事项

1. **musl vs glibc**：HarmonyOS Next 使用 musl libc，frida-server 必须使用 musl 版本
2. **Git Bash 路径问题**：在 Windows 上通过 hdc shell 执行命令时，`/data/local/tmp/` 等路径可能被 Git Bash 转义，建议用双引号包裹命令
3. **frida-server 随模拟器重启**：模拟器重启后 frida-server 和端口转发都需要重新设置
4. **x86_64 架构**：模拟器是 x86_64，如果目标应用包含 ARM native so，需要确认模拟器是否有翻译层
5. **HDC 命令**：HarmonyOS 用 hdc 而非 adb，语法类似但不完全相同




● User approved Claude's plan
  ⎿  Plan saved to: ~\.claude\plans\agile-gliding-quiche.md · /plan to edit
     Frida Hook Native 位置返回结果 — 实施计划

     目标

     编写一个 Frida hook 脚本 (hook.js)，拦截 HarmonyOS Next 应用 com.example.sys_verify 的 Native 层位置数据，实现：
     1. 监控：打印原始经纬度等位置信息
     2. 篡改：可选地将返回的位置替换为自定义假坐标

     核心原理

     数据流与 Hook 点

     JS (NativeLocationUtil.ets)
       → NAPI NativeGetCurrentLocation (libentry.so)
         → OH_Location_StartLocating (liblocation_ndk.so)
           → [系统回调，位置服务线程]
             → OnLocationUpdate (libentry.so 内部)
               → OH_LocationInfo_GetBasicInfo (liblocation_ndk.so)  ← 主要 Hook 点
               → Location_BasicInfo 结构体（按值返回）
             → CallJs (JS 线程，Promise resolve)

     主要 Hook 目标: liblocation_ndk.so 导出函数 OH_LocationInfo_GetBasicInfo

     x86_64 ABI 关键细节

     OH_LocationInfo_GetBasicInfo 返回 Location_BasicInfo 结构体（约 72 字节）。由于超过 16 字节，System V AMD64 ABI 使用隐式第一参数（返回缓冲区指针）：
     - args[0] = 返回缓冲区指针（隐式）
     - args[1] = const Location_Info*（实际参数）

     在 onLeave 中，从 args[0] 读取/修改已填充的结构体数据。

     Location_BasicInfo 结构体布局（推断自 napi_init.cpp:141-153）

     偏移  大小  类型      字段
     0     8     double    latitude
     8     8     double    longitude
     16    8     double    altitude
     24    8     double    accuracy
     32    8     double    speed
     40    8     double    direction
     48    8     int64_t   timeForFix
     56    8     int64_t   timeSinceBoot
     64    4     int32_t   locationSourceType

     实施步骤

     步骤 1：创建 hook.js 文件

     文件路径: C:\Master\Harmony\openHarmony\sys_verify\hook.js

     脚本分为以下模块：

     A. 配置区（文件顶部）

     var CONFIG = {
         FAKE_LOCATION_ENABLED: true,
         FAKE_LATITUDE:  40.7580,    // 可改为任意坐标
         FAKE_LONGITUDE: -73.9855,
         FAKE_ALTITUDE:  10.0,
         FAKE_ACCURACY:  5.0,
         FAKE_SPEED:     0.0,
         FAKE_DIRECTION: 0.0,
         TRACE_ENABLED: true,
         HEX_DUMP_ENABLED: false,   // 首次运行建议开启，验证结构体布局
     };

     B. 结构体读写工具函数

     - readBasicInfo(ptr) — 按偏移读取 Location_BasicInfo 各字段
     - writeBasicInfo(ptr, info) — 按偏移写入修改后的值
     - formatBasicInfo(info) — 格式化输出为 JSON 字符串
     - validateBasicInfo(info) — 校验 lat/lon 是否在合理范围（-90~90 / -180~180），若异常说明结构体偏移有误

     C. 主 Hook — OH_LocationInfo_GetBasicInfo

     Interceptor.attach(addr, {
         onEnter: function(args) {
             this.returnBuf = args[0];   // 保存返回缓冲区指针
         },
         onLeave: function(retval) {
             var info = readBasicInfo(this.returnBuf);  // 读取原始数据
             console.log("[ORIGINAL] " + formatBasicInfo(info));

             if (CONFIG.FAKE_LOCATION_ENABLED) {
                 writeBasicInfo(this.returnBuf, {
                     latitude: CONFIG.FAKE_LATITUDE,
                     longitude: CONFIG.FAKE_LONGITUDE,
                     // ... 保留 timeForFix/timeSinceBoot/sourceType 不变
                 });
                 console.log("[FAKE] Location overridden");
             }
         }
     });

     策略：使用 Interceptor.attach 而非 replace，让原函数正常填充结构体后再修改，避免需要了解原函数完整实现。

     D. 辅助追踪 Hook — 其他 OH_Location_* 函数

     对 liblocation_ndk.so 中的以下函数附加 Interceptor.attach 进行日志追踪（不修改行为）：
     - OH_Location_IsLocatingEnabled
     - OH_Location_CreateRequestConfig
     - OH_Location_StartLocating
     - OH_Location_StopLocating
     - OH_Location_DestroyRequestConfig

     这些函数直接 findExportByName 查找，找到就 hook，未找到仅打日志。

     E. 延迟加载处理

     liblocation_ndk.so 可能在 Frida attach 时尚未加载。处理方式：
     1. 先尝试立即 hook（Process.findModuleByName）
     2. 若未加载，hook dlopen，检测目标 so 加载后自动执行 hook
     3. 兜底：100ms 间隔轮询，最多 50 次（5 秒超时）

     F. 启动信息输出

     打印配置信息、已加载模块列表（筛选含 location/entry/napi 关键字的模块）。

     步骤 2：记录使用方法

     在脚本顶部以注释形式记录运行命令：

     # 1. 启动 frida-server
     hdc shell "nohup /data/local/tmp/frida-server -D > /dev/null 2>&1 &"

     # 2. 端口转发
     hdc fport tcp:27042 tcp:27042

     # 3. 运行 hook（attach 模式）
     frida -H 127.0.0.1:27042 -n com.example.sys_verify -l hook.js

     # 或 spawn 模式
     frida -H 127.0.0.1:27042 -f com.example.sys_verify -l hook.js --no-pause

     关键参考文件

     | 文件                                            | 作用                                             |
     |-------------------------------------------------|--------------------------------------------------|
     | entry/src/main/cpp/napi_init.cpp                | Native 层完整实现，Hook 目标的函数调用与数据结构 |
     | entry/src/main/cpp/CMakeLists.txt               | 确认库名 libentry.so，链接 liblocation_ndk.so    |
     | entry/src/main/ets/utils/NativeLocationUtil.ets | ArkTS 侧 NAPI 调用方式                           |
     | entry/src/main/cpp/types/libentry/Index.d.ts    | NAPI 导出接口定义                                |
     | Frida-Setup-Guide.md                            | Frida 环境配置参考                               |

     风险与注意事项

     1. 结构体偏移验证：首次运行建议开启 HEX_DUMP_ENABLED，确认 Location_BasicInfo 的实际内存布局与推断一致。若 lat/lon 值超出合理范围，说明偏移有误。
     2. 线程安全：OH_LocationInfo_GetBasicInfo 在位置服务线程调用，Frida Interceptor.attach 是线程安全的，每个调用有独立 this 上下文。
     3. libentry.so NAPI 函数：NativeIsLocationEnabled/NativeGetCurrentLocation 是 static C++ 函数，不一定出现在导出表中。若 findExportByName 返回 null，可忽略——主 hook 在 liblocation_ndk.so 层已生效。
     4. musl 环境兼容：frida-server 必须使用 musl 编译版本，参见 Frida-Setup-Guide.md。
