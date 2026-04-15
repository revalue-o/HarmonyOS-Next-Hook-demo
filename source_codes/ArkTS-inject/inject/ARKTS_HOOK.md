# ArkTS 层位置伪造：requireNapi Hook
**本文档为简单总结，详细技术细节请移步 ../README.md**

## 攻击效果

在 HarmonyOS Next 应用中，`geoLocationManager.getCurrentLocation()` 返回伪造的 GPS 坐标。

## 覆盖的 API

通过 Hook `globalThis.requireNapi`，拦截所有 ArkTS 模块加载。当目标模块被 import 时，返回包含伪造方法的对象：

```
import { geoLocationManager } from '@kit.LocationKit'
         ↓ 底层调用
requireNapi('geoLocationManager')  ← 在此拦截
         ↓ 返回
包含伪造 getCurrentLocation 的对象
```

被 Hook 的方法：

| API | 行为 |
|-----|------|
| `geoLocationManager.getCurrentLocation(request)` | 调用原函数获取真实位置，篡改 `latitude`/`longitude` 后返回 |

其他模块 (AbilityContext、WindowStage、abilityAccessCtrl 等) 正常透传，不受影响。

## 为什么 Hook requireNapi

NAPI 导出对象的属性是 frozen + non-configurable 的，无法直接替换其上的 `getCurrentLocation`：

```
gm.getCurrentLocation = fn     → ❌ "Cannot assign to read only property"
Object.defineProperty(gm, ...) → ❌ "Cannot define property"
```

但 `globalThis.requireNapi` 是全局函数，可以替换。import 语句底层通过它加载模块，所以在它返回对象时做替换即可。

## .abc 字节码注入方式

Ark 引擎的 CDP `callFunctionOn` 不接受 JS 源码，只接受 **base64 编码的 .abc (Ark Bytecode)**：

```
JS 源码 (.js) → es2abc 编译 → .abc 字节码 → base64 编码 → 嵌入 CDP JSON
```

注入链路：

```
ptrace attach → 启动 Ark Inspector 调试服务器 (StartDebugForSocketpair)
  → WebSocket 握手
  → CDP: Debugger.enable + Debugger.pause
  → 等待 Debugger.paused (EntryAbility.ts)
  → CDP: Debugger.resume → 等待第二次 Debugger.paused (lineNumber:5)
  → CDP: callFunctionOn({ functionDeclaration: "<base64 .abc>" })
  → CDP: Debugger.resume + Debugger.disable
  → ptrace detach
```

第二次 Pause 时，Index.ets 尚未加载。注入的 .abc 替换 `requireNapi`，resume 后 APP 加载 Index.ets 时 import 被拦截。

## .abc 源码 (monkey_patch_scope.js)

```javascript
try {
    var origRN = globalThis.requireNapi;
    globalThis.requireNapi = function(mod) {
        var r = origRN(mod);
        if (mod === "geoLocationManager" && r && typeof r.getCurrentLocation === "function") {
            var origGCL = r.getCurrentLocation;
            var hooked = {};
            Object.getOwnPropertyNames(r).forEach(function(k) {
                try { hooked[k] = r[k]; } catch(e) {}
            });
            hooked.getCurrentLocation = function(req) {
                return origGCL.call(r, req).then(function(loc) {
                    if (loc) {
                        loc.latitude = 39.9087;
                        loc.longitude = 116.3977;
                    }
                    return loc;
                });
            };
            return hooked;
        }
        return r;
    };
} catch(e) { }
```


```javascript
try {
    var origRN = globalThis.requireNapi;
    globalThis.requireNapi = function(mod) {
        var r = origRN(mod);
        if (mod === "geoLocationManager" && r && typeof r.getCurrentLocation === "function") {
            var origGCL = r.getCurrentLocation;
            var hooked = {};
            Object.getOwnPropertyNames(r).forEach(function(k) {
                try { hooked[k] = r[k]; } catch(e) {}
            });
            hooked.getCurrentLocation = function(req) {
                return origGCL.call(r, req).then(function(loc) {
                    if (loc) {
                        loc.latitude = 39.9087;
                        loc.longitude = 116.3977;
                    }
                    return loc;
                });
            };
            return hooked;
        }
        return r;
    };
} catch(e) { }
```

## 前提条件

- 已 root 的 HarmonyOS Next 设备/模拟器
- 目标 APP 以调试模式启动 (`aa start -D`)
- ptrace 可用
