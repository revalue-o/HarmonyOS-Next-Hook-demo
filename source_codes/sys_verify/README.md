# Native 层 Hook：PLT Hook 位置伪造

## 概述

本项目在 HarmonyOS Next (x86_64 模拟器) 上通过 **PLT Hook** 修改 `OH_LocationInfo_GetBasicInfo` 函数返回的位置信息。通过 ptrace 注入修改 PLT stub，使函数返回伪造的经纬度坐标。

## 技术原理

### Hook 目标

应用 (`libentry.so`) 通过 PLT/GOT 调用 `liblocation_ndk.so` 中的 `OH_LocationInfo_GetBasicInfo(Location_Info*)` 获取位置信息。函数使用 sret 调用约定，将 `Location_BasicInfo` 结构体写入 `rdi` 指向的缓冲区。

### PLT Hook 流程

```
正常调用: libentry.so → PLT stub → jmp [GOT] → liblocation_ndk.so 原函数
Hook 后:  libentry.so → PLT stub → jmp [hook_addr] → trampoline
                                                    → 调用原函数
                                                    → 覆写 lat/lon
                                                    → ret
```

注入步骤：
1. ptrace ATTACH 目标进程
2. 解析 `/proc/pid/maps` 找到 `libentry.so` 和 `ld-musl` 的内存布局
3. 解析 ELF 动态节，找到 `OH_LocationInfo_GetBasicInfo` 的 GOT 条目
4. 在代码段中搜索跳转到该 GOT 的 PLT stub
5. 在 ld-musl 的 code cave 中执行 mmap syscall，分配匿名可执行内存
6. 将 hook trampoline 写入 mmap 区域
7. 将 PLT stub 替换为跳转到 hook 的指令
8. ptrace DETACH

详细技术文档见 [inject/README.md](inject/README.md)。

## 目录结构

```
sys_verify/
├── AppScope/                  # 应用级配置和资源
├── entry/                     # 主模块
│   ├── src/main/
│   │   ├── cpp/
│   │   │   └── napi_init.cpp  # NAPI 模块 (封装 OH_Location_* API)
│   │   ├── ets/
│   │   │   ├── pages/Index.ets           # 主界面 (ArkTS + Native 获取位置)
│   │   │   └── utils/
│   │   │       ├── LocationUtil.ets      # ArkTS 层位置服务
│   │   │       └── NativeLocationUtil.ets # Native 层位置服务
│   │   └── module.json5       # 模块配置 (权限声明)
├── inject/                    # Hook 注入工具
│   ├── inject_v6.c            # PLT Hook 实现 (当前版本)
│   ├── inject_v6              # 编译后的二进制
│   └── README.md              # 详细技术文档
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

用 DevEco Studio 打开 `sys_verify` 目录，编译并安装到模拟器。

### 2. 编译注入工具

```bash
CLANG="C:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/native/llvm/bin/clang.exe"
SYSROOT="C:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/native/sysroot"

"$CLANG" --target=x86_64-linux-ohos -O2 --sysroot="$SYSROOT" -o inject_v6 inject_v6.c
```

### 3. 推送并注入

```bash
# 推送注入工具
hdc file send inject_v6 /data/local/tmp/inject_v6

# 启动目标应用
hdc shell aa start -a EntryAbility -b com.example.sys_verify

# 获取 PID
hdc shell ps -ef | grep sys_verify

# 执行注入
hdc shell /data/local/tmp/inject_v6 <PID>
```

### 4. 验证

在应用中点击 "获取位置 (Native)" 按钮，应显示伪造坐标 `lat=39.908700, lon=116.397500`。

### 修改伪造坐标

编辑 `inject_v6.c` 顶部的常量后重新编译：
```c
static double g_fake_lat = 39.9087;   /* 纬度 */
static double g_fake_lon = 116.3975;  /* 经度 */
```

## 局限性

1. 仅影响 Native 层 (`OH_LocationInfo_GetBasicInfo`)，不影响 ArkTS 层 (`geoLocationManager`)
2. 需要 root 权限 (ptrace + /proc/pid/mem)
3. 仅在 x86_64 模拟器上测试通过
4. 应用重启后需重新注入
