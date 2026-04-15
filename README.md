# HarmonyOS Next Hook Demo

本项目为华为鸿蒙系统 (HarmonyOS Next) 的应用层安全研究 Demo，从 **Native**、**NAPI**、**ArkTS** 三个层面对位置 API 进行 Hook，同时包含一个调用系统完整性远程校验 API 的应用。三个方向的 Hook 均已成功。

## 三层 Hook 技术简述

### Native 层 — PLT Hook

**原理**：通过 ptrace 注入目标进程，修改 `libentry.so` 的 PLT (Procedure Linkage Table) stub，使 `OH_LocationInfo_GetBasicInfo` 的跨库调用先跳转到自定义 trampoline。Trampoline 调用原函数后覆写 `Location_BasicInfo` 结构体中的经纬度字段。

**特点**：数据层修改 — 原函数仍然执行，但返回值被篡改。

```
调用链: libentry.so → PLT stub (被修改) → hook trampoline → 调用原函数 → 覆写 lat/lon → ret
```

### NAPI 层 — Inline Hook

**原理**：直接覆写 `NativeGetCurrentLocation` 函数入口的机器码（16 字节 patch: `jmp [rip+0]; <addr>`），跳转到 mmap 区域中的 `fake_getLocation` 纯汇编函数。Fake 函数使用 NAPI API（`napi_create_promise`、`napi_create_object`、`napi_create_double` 等）构造包含伪造坐标的 Promise 返回值。

**特点**：代码层替换 — 原函数代码不再执行，完全由自定义函数接管。

```
调用链: JS 引擎调用 NativeGetCurrentLocation → 入口被覆写 → fake_getLocation (纯汇编) → 构造伪造坐标 → 返回 Promise
```

### ArkTS 层 — CDP Inspector 字节码注入

**原理**：通过 ptrace 启动 Ark Inspector 调试服务器，建立 WebSocket 连接，使用 CDP (Chrome DevTools Protocol) 在特定断点处通过 `callFunctionOn` 注入 base64 编码的 `.abc` 字节码。注入的字节码替换 `globalThis.requireNapi`，当应用加载 `geoLocationManager` 模块时返回包含伪造 `getCurrentLocation` 的代理对象。

**特点**：运行时字节码注入 — 无需修改 APK，通过调试协议注入自定义逻辑。

```
注入链: ptrace → StartDebugForSocketpair → WebSocket → CDP Debugger.pause → callFunctionOn(.abc) → monkey-patch requireNapi
```

## 项目结构

```
HarmonyOS Next Hook demo/
├── README.md                          # 本文件
├── source_codes/
│   ├── sys_verify/                    # Native 层 Hook (PLT Hook)
│   │   ├── inject/
│   │   │   ├── inject_v6.c            # PLT Hook 实现
│   │   │   └── README.md              # PLT Hook 技术文档
│   │   ├── entry/                     # 目标应用源码 (位置服务 Demo)
│   │   └── README.md                  # 安装与使用指南
│   │
│   ├── NAPI_hook/                     # NAPI 层 Hook (Inline Hook)
│   │   ├── inject/
│   │   │   ├── inject_napi.c          # Inline Hook 实现
│   │   │   ├── inject.bat             # 一键编译+注入脚本
│   │   │   └── NAPI_HOOK_REPORT.md    # NAPI Hook 技术报告
│   │   ├── entry/                     # 目标应用源码
│   │   └── README.md                  # 安装与使用指南
│   │
│   ├── ArkTS-inject/                  # ArkTS 层 Hook (CDP 字节码注入)
│   │   ├── inject/
│   │   │   ├── inject_debugger.c      # CDP Inspector 注入器
│   │   │   ├── monkey_patch_scope.js  # Monkey-patch 源码
│   │   │   ├── monkey_patch_scope.abc # 编译后的 .abc 字节码
│   │   │   ├── run_inject.bat         # 一键注入脚本
│   │   │   └── ARKTS_HOOK.md          # ArkTS Hook 技术文档
│   │   ├── entry/                     # 目标应用源码
│   │   └── README.md                  # 安装与使用指南
│   │
│   └── sys_integrity/                 # 系统完整性远程校验 API 调用
│       ├── entry/                     # 应用源码
│       ├── CORE_CODE.md               # 核心代码文档
│       └── README.md                  # 安装与使用指南
│
└── haps/                              # 各应用的 .hap 安装包
    ├── ArkTS&Native.hap               # sys_verify / ArkTS-inject 应用
    ├── NAPI.hap                       # NAPI_hook 应用
    └── sys_integrity-signed.hap       # sys_integrity 应用
```

## 环境要求

华为未提供 HarmonyOS Next 的官方 root 方法。因为Hook 作为侵入式技术需要 root 权限，环境采用社区给出的 root 模拟器：

- Root 教程：https://wuxianlin.com/2024/10/27/root-harmonyos-next-emultor/
- 模拟器仓库：https://github.com/wuxianlin/harmonyos_next_emulator_mod
**请注意，该模拟器使用旧版API，这会影响ArkTS Hook的.abc字节码的编译命令**

通用要求：
- DevEco Studio + HarmonyOS SDK
- hdc (HarmonyOS Device Connector)
- HarmonyOS SDK 自带的 clang 工具链（编译注入工具）
- x86_64 模拟器

## 快速开始

每个子目录下都有独立的 README.md，包含详细的安装和使用指南。以下为通用步骤：

### Native 层 Hook

```bash
# 1. 用 DevEco Studio 编译安装 sys_verify 应用
# 2. 编译注入工具
"$CLANG" --target=x86_64-linux-ohos -O2 --sysroot="$SYSROOT" -o inject_v6 inject_v6.c
# 3. 注入
hdc shell aa start -a EntryAbility -b com.example.sys_verify
hdc shell /data/local/tmp/inject_v6 <PID>
# 4. 在应用中点击 "获取位置 (Native)" → 显示伪造坐标
```

详见 [source_codes/sys_verify/README.md](source_codes/sys_verify/README.md)。

### NAPI 层 Hook

```bash
# 1. 用 DevEco Studio 编译安装 NAPI_hook 应用
# 2. 编译注入工具
"$CLANG" --target=x86_64-linux-ohos -O2 --sysroot="$SYSROOT" -o inject_napi inject_napi.c -ldl
# 3. 注入
hdc shell aa start -a EntryAbility -b com.example.sys_verify
hdc shell /data/local/tmp/inject_napi <PID>
# 4. 在应用中点击 "Get Location" → 显示伪造坐标
```

详见 [source_codes/NAPI_hook/README.md](source_codes/NAPI_hook/README.md)。

### ArkTS 层 Hook

```bash
# 1. 用 DevEco Studio 编译安装 ArkTS-inject 应用
# 2. 编译注入工具
"$CLANG" --target=x86_64-linux-ohos -O2 --sysroot="$SYSROOT" -o inject_debugger inject_debugger.c
# 3. 必须用调试模式启动
hdc shell "aa start -D -a EntryAbility -b com.example.sys_verify"
# 4. 注入
hdc shell /data/local/tmp/inject_debugger <PID>
# 5. 在应用中点击 "获取位置" → 显示伪造坐标
```

详见 [source_codes/ArkTS-inject/README.md](source_codes/ArkTS-inject/README.md)。

### 系统完整性校验

```bash
# 用 DevEco Studio 编译安装 sys_integrity 应用
# 打开应用，点击 "系统完整性" 按钮
```
**本应用由本人签名，在本人设备上验证成功，不保证他人设备上也能成功**

详见 [source_codes/sys_integrity/README.md](source_codes/sys_integrity/README.md)。

## 免责声明

本项目仅供安全研究和学习用途。Hook 技术的使用应遵守相关法律法规，不得用于非法目的。
