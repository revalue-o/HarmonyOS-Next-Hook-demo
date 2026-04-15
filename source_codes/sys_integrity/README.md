# 系统完整性远程校验 API 调用应用

## 概述

本应用演示如何调用华为 Device Security Kit 的 `safetyDetect.checkSysIntegrity()` API，实现系统完整性远程校验。检测内容包括越狱检测、模拟器检测、攻击检测和基本完整性评估。

同时提供 ArkTS 层和 Native 层两种位置服务实现，可用于对比测试。

## 功能

### 系统完整性检测

- 调用 `safetyDetect.checkSysIntegrity()` API
- 生成随机 Nonce（16-66 字节 Base64 编码）
- 解析 JWS (JSON Web Signature) 格式的响应
- 检测项：越狱 (jailbreak)、模拟器 (emulator)、攻击 (attack)、基本完整性 (basicIntegrity)

### 位置服务

- **ArkTS 层**：通过 `@kit.LocationKit` 的 `geoLocationManager` API
- **Native 层**：通过 NAPI 封装的 `OH_Location_*` C API

## 目录结构

```
sys_integrity/
├── AppScope/                  # 应用级配置和资源
├── entry/                     # 主模块
│   ├── src/main/
│   │   ├── cpp/
│   │   │   ├── napi_init.cpp  # NAPI 模块 (Native 层位置服务)
│   │   │   └── CMakeLists.txt
│   │   ├── ets/
│   │   │   ├── pages/Index.ets           # 主界面
│   │   │   ├── entryability/EntryAbility.ets
│   │   │   └── utils/
│   │   │       ├── SecurityCheckUtil.ets  # 系统完整性检测工具类
│   │   │       ├── LocationUtil.ets       # ArkTS 层位置服务
│   │   │       └── NativeLocationUtil.ets # Native 层位置服务
│   │   └── module.json5       # 模块配置 (权限声明)
├── CORE_CODE.md               # 核心代码文档
├── build-profile.json5
└── oh-package.json5
```

## 环境要求

- HarmonyOS Next 设备或模拟器
- DevEco Studio + HarmonyOS SDK (API 13+)
- Device Security Kit (`@kit.DeviceSecurityKit`)

## 安装与使用

### 1. 编译并安装

用 DevEco Studio 打开 `sys_integrity` 目录，编译并安装到设备。

### 2. 授予权限

应用首次启动需授予位置权限。

### 3. 使用

- 点击 **"获取位置"** 按钮获取当前位置信息
- 点击 **"系统完整性"** 按钮执行完整性检测

## 权限配置

`module.json5` 中声明的权限：
- `ohos.permission.LOCATION` — 精确位置
- `ohos.permission.APPROXIMATELY_LOCATION` — 大概位置
- `ohos.permission.INTERNET` — 网络访问

## 核心代码说明

详细代码说明见 [CORE_CODE.md](CORE_CODE.md)。

### SecurityCheckUtil.ets

- `checkSystemIntegrity()` — 调用 `safetyDetect.checkSysIntegrity()` 并解析 JWS 响应
- `generateNonce()` — 生成 32 字节随机 Nonce
- `parseJWS()` — 解析 `header.payload.signature` 格式的 JWS
- `base64Decode()` — 手动实现 Base64 解码（ArkTS 不支持 `atob()`）
