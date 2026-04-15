/**
 * Frida Hook 脚本 — 拦截 HarmonyOS Next Native 层位置返回结果
 *
 * 目标应用: com.example.sys_verify
 * 目标库:   liblocation_ndk.so (OH_Location_* API)
 *
 * 使用方法:
 *   1. 启动 frida-server:
 *      hdc shell "nohup /data/local/tmp/frida-server -D > /dev/null 2>&1 &"
 *   2. 端口转发:
 *      hdc fport tcp:27042 tcp:27042
 *   3. 运行 (attach 模式):
 *      frida -H 127.0.0.1:27042 -n com.example.sys_verify -l hook.js
 *   4. 或 spawn 模式 (重启应用):
 *      frida -H 127.0.0.1:27042 -f com.example.sys_verify -l hook.js --no-pause
 */

// ============================================================
// 配置区 — 在此修改假坐标和开关
// ============================================================

var CONFIG = {
    // 是否启用位置篡改 (false = 仅监控，true = 监控+篡改)
    FAKE_LOCATION_ENABLED: true,

    // 假 GPS 坐标 (默认: 北京天安门)
    FAKE_LATITUDE:  39.9087,
    FAKE_LONGITUDE: 116.3975,
    FAKE_ALTITUDE:  50.0,
    FAKE_ACCURACY:  5.0,
    FAKE_SPEED:     0.0,
    FAKE_DIRECTION: 0.0,

    // 是否打印所有 OH_Location_* 函数调用追踪
    TRACE_ENABLED: true,

    // 是否打印 Location_BasicInfo 的 hex dump (首次运行建议开启以验证偏移)
    HEX_DUMP_ENABLED: false,

    // 目标模块名
    LOCATION_NDK_MODULE: "liblocation_ndk.so",
    ENTRY_MODULE:        "libentry.so",
};

// ============================================================
// Location_BasicInfo 结构体工具函数 (x86_64 偏移)
//
// 推断自 napi_init.cpp 中字段使用顺序:
//   latitude, longitude, altitude, accuracy, speed, direction,
//   timeForFix, timeSinceBoot, locationSourceType
//
// 偏移:
//   0:  double latitude
//   8:  double longitude
//   16: double altitude
//   24: double accuracy
//   32: double speed
//   40: double direction
//   48: int64  timeForFix
//   56: int64  timeSinceBoot
//   64: int32  sourceType
// ============================================================

var BASIC_INFO_SIZE = 72;

function readBasicInfo(ptr) {
    return {
        latitude:      ptr.readDouble(0),
        longitude:     ptr.readDouble(8),
        altitude:      ptr.readDouble(16),
        accuracy:      ptr.readDouble(24),
        speed:         ptr.readDouble(32),
        direction:     ptr.readDouble(40),
        timeForFix:    ptr.readS64(48),
        timeSinceBoot: ptr.readS64(56),
        sourceType:    ptr.readS32(64),
    };
}

function writeBasicInfo(ptr, info) {
    ptr.writeDouble(info.latitude, 0);
    ptr.writeDouble(info.longitude, 8);
    ptr.writeDouble(info.altitude, 16);
    ptr.writeDouble(info.accuracy, 24);
    ptr.writeDouble(info.speed, 32);
    ptr.writeDouble(info.direction, 40);
    ptr.writeS64(info.timeForFix, 48);
    ptr.writeS64(info.timeSinceBoot, 56);
    ptr.writeS32(info.sourceType, 64);
}

function formatBasicInfo(info) {
    return JSON.stringify({
        latitude:      info.latitude,
        longitude:     info.longitude,
        altitude:      info.altitude,
        accuracy:      info.accuracy,
        speed:         info.speed,
        direction:     info.direction,
        timeForFix:    info.timeForFix.toString(),
        timeSinceBoot: info.timeSinceBoot.toString(),
        sourceType:    info.sourceType,
    }, null, 2);
}

function validateBasicInfo(info) {
    if (Math.abs(info.latitude) > 90 || Math.abs(info.longitude) > 180) {
        console.log("[!] WARNING: lat=" + info.latitude + " lon=" + info.longitude +
                    " out of range! Struct layout may be incorrect.");
        console.log("[!] Enable HEX_DUMP_ENABLED to inspect raw bytes.");
        return false;
    }
    return true;
}

// ============================================================
// 主 Hook — OH_LocationInfo_GetBasicInfo
//
// 这个函数从 Location_Info 提取 Location_BasicInfo 结构体。
// x86_64 System V ABI: 结构体 >16 字节通过隐式第一参数返回:
//   args[0] = 返回缓冲区指针 (隐式)
//   args[1] = const Location_Info* (实际参数)
//
// 策略: Interceptor.attach, 在 onLeave 中修改已填充的缓冲区
// ============================================================

function hookGetBasicInfo(mod) {
    var addr = mod.findExportByName("OH_LocationInfo_GetBasicInfo");
    if (!addr) {
        console.log("[-] OH_LocationInfo_GetBasicInfo not found in " + mod.name);
        console.log("[*] Listing location-related exports for debugging:");
        mod.enumerateExports().forEach(function (e) {
            if (e.name.indexOf("Location") !== -1 || e.name.indexOf("location") !== -1) {
                console.log("    " + e.type + " " + e.name + " @ " + e.address);
            }
        });
        return;
    }
    console.log("[+] OH_LocationInfo_GetBasicInfo @ " + addr);

    Interceptor.attach(addr, {
        onEnter: function (args) {
            // x86_64 sret: args[0] = 返回缓冲区, args[1] = Location_Info*
            this.returnBuf = args[0];
            if (CONFIG.TRACE_ENABLED) {
                console.log("[TRACE] OH_LocationInfo_GetBasicInfo called");
                console.log("        returnBuf=" + args[0] + " locationInfo=" + args[1]);
            }
        },
        onLeave: function (retval) {
            if (this.returnBuf.isNull()) {
                console.log("[!] Return buffer is null, skipping");
                return;
            }

            var original = readBasicInfo(this.returnBuf);

            if (!validateBasicInfo(original)) {
                console.log("[HEX] Raw bytes for debugging:");
                console.log(hexdump(this.returnBuf, { length: BASIC_INFO_SIZE, ansi: true }));
                return;
            }

            console.log("[LOCATION] Original Location_BasicInfo:");
            console.log(formatBasicInfo(original));

            if (CONFIG.HEX_DUMP_ENABLED) {
                console.log("[HEX] BasicInfo raw bytes:");
                console.log(hexdump(this.returnBuf, { length: BASIC_INFO_SIZE, ansi: true }));
            }

            if (CONFIG.FAKE_LOCATION_ENABLED) {
                var fake = {
                    latitude:      CONFIG.FAKE_LATITUDE,
                    longitude:     CONFIG.FAKE_LONGITUDE,
                    altitude:      CONFIG.FAKE_ALTITUDE,
                    accuracy:      CONFIG.FAKE_ACCURACY,
                    speed:         CONFIG.FAKE_SPEED,
                    direction:     CONFIG.FAKE_DIRECTION,
                    timeForFix:    original.timeForFix,
                    timeSinceBoot: original.timeSinceBoot,
                    sourceType:    original.sourceType,
                };
                writeBasicInfo(this.returnBuf, fake);
                console.log("[FAKE] Location overridden => lat=" + fake.latitude +
                            " lon=" + fake.longitude + " alt=" + fake.altitude +
                            " acc=" + fake.accuracy);
            }
        }
    });
}

// ============================================================
// 辅助追踪 — 其他 OH_Location_* 函数
// ============================================================

function hookLocationNdkTracing(mod) {
    var targets = [
        {
            name: "OH_Location_IsLocatingEnabled",
            onEnter: function (args) {
                this.enabledPtr = args[0];
                console.log("[TRACE] OH_Location_IsLocatingEnabled called, enabledPtr=" + args[0]);
            },
            onLeave: function (retval) {
                var resultCode = retval.toInt32();
                var enabled = this.enabledPtr.isNull() ? "?" : this.enabledPtr.readU8();
                console.log("[TRACE] OH_Location_IsLocatingEnabled => code=" + resultCode +
                            " enabled=" + enabled);
            },
        },
        {
            name: "OH_Location_CreateRequestConfig",
            onEnter: function () {
                console.log("[TRACE] OH_Location_CreateRequestConfig called");
            },
            onLeave: function (retval) {
                console.log("[TRACE] OH_Location_CreateRequestConfig => config=" + retval);
            },
        },
        {
            name: "OH_LocationRequestConfig_SetPowerConsumptionScene",
            onEnter: function (args) {
                console.log("[TRACE] OH_LocationRequestConfig_SetPowerConsumptionScene" +
                            " config=" + args[0] + " scene=" + args[1].toInt32());
            },
        },
        {
            name: "OH_LocationRequestConfig_SetInterval",
            onEnter: function (args) {
                console.log("[TRACE] OH_LocationRequestConfig_SetInterval" +
                            " config=" + args[0] + " interval=" + args[1].toInt32());
            },
        },
        {
            name: "OH_LocationRequestConfig_SetCallback",
            onEnter: function (args) {
                console.log("[TRACE] OH_LocationRequestConfig_SetCallback" +
                            " config=" + args[0] + " callback=" + args[1] +
                            " userData=" + args[2]);
            },
        },
        {
            name: "OH_Location_StartLocating",
            onEnter: function (args) {
                console.log("[TRACE] OH_Location_StartLocating config=" + args[0]);
            },
            onLeave: function (retval) {
                console.log("[TRACE] OH_Location_StartLocating => resultCode=" + retval.toInt32());
            },
        },
        {
            name: "OH_Location_StopLocating",
            onEnter: function (args) {
                console.log("[TRACE] OH_Location_StopLocating config=" + args[0]);
            },
        },
        {
            name: "OH_Location_DestroyRequestConfig",
            onEnter: function (args) {
                console.log("[TRACE] OH_Location_DestroyRequestConfig config=" + args[0]);
            },
        },
    ];

    targets.forEach(function (t) {
        var addr = mod.findExportByName(t.name);
        if (addr) {
            console.log("[+] Tracing " + t.name + " @ " + addr);
            Interceptor.attach(addr, t);
        } else {
            console.log("[-] Export not found: " + t.name);
        }
    });
}

// ============================================================
// 延迟加载处理 — dlopen hook + 轮询兜底
// ============================================================

var locationHooked = false;

function tryHookAll() {
    if (locationHooked) return true;

    var mod = Process.findModuleByName(CONFIG.LOCATION_NDK_MODULE);
    if (!mod) return false;

    console.log("[+] " + mod.name + " loaded at " + mod.base + " size=" + mod.size);
    hookGetBasicInfo(mod);
    hookLocationNdkTracing(mod);
    locationHooked = true;
    return true;
}

function hookDlopen() {
    var dlopenAddr = Module.findExportByName(null, "dlopen");
    if (dlopenAddr) {
        Interceptor.attach(dlopenAddr, {
            onEnter: function (args) {
                try {
                    this.path = args[0].isNull() ? null : args[0].readUtf8String();
                } catch (e) {
                    this.path = null;
                }
            },
            onLeave: function () {
                if (this.path && this.path.indexOf(CONFIG.LOCATION_NDK_MODULE) !== -1) {
                    console.log("[*] " + CONFIG.LOCATION_NDK_MODULE + " loaded via dlopen");
                    setTimeout(tryHookAll, 100);
                }
            },
        });
        console.log("[+] dlopen hooked for deferred loading detection");
    }
}

// ============================================================
// 初始化
// ============================================================

console.log("============================================================");
console.log("  HarmonyOS Next Native Location Hook");
console.log("  Target:   " + CONFIG.LOCATION_NDK_MODULE);
console.log("  Fake Loc: " + (CONFIG.FAKE_LOCATION_ENABLED ? "ON" : "OFF"));
if (CONFIG.FAKE_LOCATION_ENABLED) {
    console.log("  Fake Lat: " + CONFIG.FAKE_LATITUDE);
    console.log("  Fake Lon: " + CONFIG.FAKE_LONGITUDE);
}
console.log("  Arch:     " + Process.arch);
console.log("  Platform: " + Process.platform);
console.log("============================================================");

// 列出已加载的相关模块
console.log("[*] Loaded modules (filtered):");
Process.enumerateModules().forEach(function (m) {
    if (m.name.indexOf("location") !== -1 ||
        m.name.indexOf("entry") !== -1 ||
        m.name.indexOf("napi") !== -1) {
        console.log("  " + m.name + " @ " + m.base + " size=" + m.size);
    }
});

// 尝试立即 hook
if (tryHookAll()) {
    console.log("[+] Hooks installed immediately");
} else {
    console.log("[*] " + CONFIG.LOCATION_NDK_MODULE + " not loaded yet. Waiting...");
    hookDlopen();

    // 兜底轮询: 每 200ms 检查一次, 最多 50 次 (10s)
    var pollCount = 0;
    var pollTimer = setInterval(function () {
        pollCount++;
        if (tryHookAll()) {
            console.log("[+] Hooks installed via polling");
            clearInterval(pollTimer);
        } else if (pollCount >= 50) {
            console.log("[-] Timed out waiting for " + CONFIG.LOCATION_NDK_MODULE);
            clearInterval(pollTimer);
        }
    }, 200);
}
