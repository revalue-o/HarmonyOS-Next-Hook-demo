# NAPI 层 Hook：Inline Hook 位置伪造

## 概述

本项目在 HarmonyOS Next (x86_64 模拟器) 上通过 **Inline Hook** 覆写 `NativeGetCurrentLocation` 函数入口，跳转到 mmap 区域中的 `fake_getLocation` 纯汇编函数，直接替换返回值。这是真正的代码层面替换（非数据修改），原函数代码不再执行。

## 技术原理

### Hook 目标

`NativeGetCurrentLocation` 是 `libentry.so` 中注册的 NAPI 函数，当用户点击 "Get Location" 时被 JS 引擎调用。函数通过 NAPI 异步回调获取位置并返回 Promise。

```
应用架构:
  dlopen libentry.so → RegisterEntryModule() → Init()
    → napi_define_properties() → 映射 NativeGetCurrentLocation

用户点击 "Get Location":
  JS 引擎调用 NativeGetCurrentLocation(env, callback_info)
    → OH_Location_StartLocating → 异步回调 → OH_LocationInfo_GetBasicInfo
    → 构建返回对象 → napi_resolve_deferred
```

### Inline Hook 流程

```
1. ptrace ATTACH 目标进程
2. 解析 libentry.so 的 ELF 头，读取 NAPI API 函数的真实地址（已 resolved 的 GOT 条目）
3. 在 ld-musl 的 code cave 中执行 mmap syscall，分配匿名可执行内存
4. 在 mmap 区域构造 fake_getLocation 函数（纯 x86_64 机器码）
5. 覆写 NativeGetCurrentLocation 前 16 字节：jmp [rip+0]; <fake_addr>; nop nop
6. ptrace DETACH
```

详细技术文档和调试过程见 [inject/NAPI_HOOK_REPORT.md](inject/NAPI_HOOK_REPORT.md)。

## 目录结构

```
NAPI_hook/
├── AppScope/                  # 应用级配置和资源
├── entry/                     # 主模块
│   ├── src/main/
│   │   ├── cpp/
│   │   │   └── napi_init.cpp  # NAPI 模块 (包含 NativeGetCurrentLocation)
│   │   └── ets/
│   │       ├── pages/Index.ets           # 主界面
│   │       └── entryability/EntryAbility.ets
├── inject/                    # Hook 注入工具
│   ├── inject_napi.c          # Inline Hook 注入器 (当前版本)
│   ├── inject_napi            # 编译后的二进制
│   ├── inject.bat             # 一键编译+注入脚本 (Windows)
│   └── NAPI_HOOK_REPORT.md    # 详细技术报告
├── build-profile.json5
└── oh-package.json5
```

## 环境要求

- HarmonyOS Next x86_64 模拟器 (已 root)
- DevEco Studio + HarmonyOS SDK
- 工具链：`sdk/default/openharmony/native/llvm/bin/clang.exe`
- hdc (HarmonyOS Device Connector)

Root 模拟器参考：https://wuxianlin.com/2024/10/27/root-harmonyos-next-emultor/

## 安装与使用

### 1. 编译目标应用

用 DevEco Studio 打开 `NAPI_hook` 目录，编译并安装到模拟器。

### 2. 编译注入工具

```bash
CLANG="C:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/native/llvm/bin/clang.exe"
SYSROOT="C:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/native/sysroot"

"$CLANG" --target=x86_64-linux-ohos -O2 --sysroot="$SYSROOT" \
    -o inject_napi inject_napi.c -ldl
```

### 3. 推送并注入

```bash
# 推送注入工具
hdc file send inject_napi /data/local/tmp/inject_napi

# 启动目标应用
hdc shell aa start -a EntryAbility -b com.example.sys_verify

# 获取 PID
hdc shell ps -ef | grep sys_verify

# 执行注入
hdc shell /data/local/tmp/inject_napi <PID>
```

### 4. 验证

在应用中点击 "Get Location" 按钮，应显示伪造坐标 `lat=39.9087, lon=116.3975`。

### 一键脚本

在 `inject/` 目录运行 `inject.bat`，自动完成编译 -> 推送 -> 查找 PID -> 注入全流程。

### 修改伪造坐标

编辑 `inject_napi.c` 顶部的常量后重新编译：
```c
static double g_fake_lat = 39.9087;   // 伪造纬度
static double g_fake_lon = 116.3975;  // 伪造经度
static double g_fake_alt = 50.0;      // 伪造海拔
static double g_fake_acc = 5.0;       // 伪造精度
```

## 关键技术要点

### NAPI 调用约定

`napi_create_double(env, double value, napi_value* result)` 中，`double` 通过 `xmm0` 传递，不占整数寄存器位，后续参数从 `rsi` 开始：
```
rdi=env, xmm0=value, rsi=&result  (不是 rdx!)
```

### HarmonyOS 特有限制

- **Linker namespace 隔离**：dlopen 只能加载系统路径和 bundle 路径的库，`/data/local/tmp/` 不行
- **NAPI 线程安全**：NAPI 函数不能在 ptrace 暂停的非 JS 上下文中调用
- 因此只能使用纯内存操作 (ptrace + mmap + /proc/pid/mem) + Inline Hook

## 局限性

1. 如果 `libentry.so` 重新编译，`NativeGetCurrentLocation` 的偏移可能变化，需用 `llvm-objdump` 重新确认
2. 需要 root 权限
3. 仅在 x86_64 模拟器上测试通过
4. 应用重启后需重新注入
