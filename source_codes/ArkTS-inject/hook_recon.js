/**
 * ArkTS 位置 API 侦察脚本
 *
 * 目标: 发现 geoLocationManager.getCurrentLocation() 的原生后端
 *
 * 使用方法:
 *   frida -H 127.0.0.1:27042 -n com.example.sys_verify -l hook_recon.js
 *
 * 运行后点击应用中的「获取位置 (ArkTS)」按钮,
 * 观察控制台输出中被调用的原生函数。
 */

// ============================================================
// 阶段 1: 枚举已加载模块
// ============================================================

console.log("============================================================");
console.log("  ArkTS Location API Reconnaissance");
console.log("  Arch:     " + Process.arch);
console.log("  Platform: " + Process.platform);
console.log("  PID:      " + Process.id);
console.log("============================================================\n");

var FILTERS = ["location", "napi", "ace", "ipc", "entry", "bundle"];

console.log("[*] === Phase 1: Enumerating loaded modules ===\n");

var candidateModules = [];

Process.enumerateModules().forEach(function (m) {
    var nameLower = m.name.toLowerCase();
    var matched = false;
    FILTERS.forEach(function (f) {
        if (nameLower.indexOf(f) !== -1) matched = true;
    });

    if (matched) {
        candidateModules.push(m);
        console.log("  [MOD] " + m.name);
        console.log("        base=" + m.base + " size=0x" + m.size.toString(16) +
                    " path=" + m.path);
    }
});

// ============================================================
// 阶段 2: 枚举候选模块的导出符号
// ============================================================

console.log("\n[*] === Phase 2: Enumerating exports from candidate modules ===\n");

var EXPORT_FILTERS = [
    "Location", "location", "GetCurrent", "Single",
    "Callback", "callback", "BasicInfo", "Update",
    "GeoLocation", "geoLocation", "Latitude", "Longitude",
    "Position", "position"
];

var tracedFunctions = []; // 记录所有被 trace 的函数

candidateModules.forEach(function (m) {
    var exports = m.enumerateExports();
    var relevantExports = [];

    exports.forEach(function (e) {
        var matched = false;
        EXPORT_FILTERS.forEach(function (f) {
            if (e.name.indexOf(f) !== -1) matched = true;
        });
        if (matched) relevantExports.push(e);
    });

    if (relevantExports.length > 0) {
        console.log("  --- " + m.name + " (" + relevantExports.length + " relevant exports) ---");
        relevantExports.forEach(function (e) {
            console.log("    " + e.type + " " + e.name + " @ " + e.address);
            // 收集可 trace 的函数 (排除太频繁的通用函数)
            if (e.type === "function") {
                var skip = false;
                // 跳过太泛的符号，避免海量输出
                var skipPatterns = ["napi_", "NAPI_"];
                skipPatterns.forEach(function (p) {
                    if (e.name.indexOf(p) !== -1) skip = true;
                });
                if (!skip) {
                    tracedFunctions.push({
                        name: e.name,
                        address: e.address,
                        module: m.name
                    });
                }
            }
        });
        console.log("");
    }
});

// ============================================================
// 阶段 3: Hook dlopen 监听延迟加载
// ============================================================

console.log("[*] === Phase 3: Hooking dlopen for deferred loading ===\n");

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
            if (this.path) {
                var pathLower = this.path.toLowerCase();
                if (pathLower.indexOf("location") !== -1 ||
                    pathLower.indexOf("geo") !== -1 ||
                    pathLower.indexOf("napi") !== -1) {
                    console.log("[DLOADED] " + this.path);
                    console.log("  backtrace:\n" +
                        Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n"));
                }
            }
        }
    });
    console.log("[+] dlopen hooked\n");
}

// ============================================================
// 阶段 4: 对候选函数安装 trace 钩子
//
// 仅打印调用信息，不修改任何数据。
// 用户点击「获取位置 (ArkTS)」后观察哪些函数被触发。
// ============================================================

console.log("[*] === Phase 4: Installing trace hooks on " +
            tracedFunctions.length + " candidate functions ===\n");

var hookedCount = 0;
var MAX_TRACE_HOOKS = 60; // 限制 trace 数量避免性能问题

tracedFunctions.slice(0, MAX_TRACE_HOOKS).forEach(function (f) {
    try {
        Interceptor.attach(f.address, {
            onEnter: function (args) {
                console.log("[CALLED] " + f.name + " (" + f.module + ")");
                console.log("  args[0]=" + args[0] + " args[1]=" + args[1] +
                            " args[2]=" + args[2] + " args[3]=" + args[3]);
            },
            onLeave: function (retval) {
                console.log("[RETURN] " + f.name + " => " + retval);
            }
        });
        hookedCount++;
    } catch (e) {
        console.log("[TRACE-ERR] " + f.name + ": " + e);
    }
});

console.log("\n[+] Successfully installed " + hookedCount + " trace hooks");
if (tracedFunctions.length > MAX_TRACE_HOOKS) {
    console.log("[*] Skipped " + (tracedFunctions.length - MAX_TRACE_HOOKS) +
                " functions (limit reached)");
}

// ============================================================
// 阶段 5: 额外侦察 — 检查 NAPI 模块注册
// ============================================================

console.log("\n[*] === Phase 5: Checking NAPI module registration ===\n");

// 尝试 hook napi_define_properties 来发现 geoLocationManager 的注册
var napiDefineProps = Module.findExportByName("libace_napi.z.so",
    "napi_define_properties");
if (napiDefineProps) {
    console.log("[+] napi_define_properties found @ " + napiDefineProps);
    console.log("    (Not hooking — too noisy. Available if needed.)");
}

// 检查 napi_create_double — 位置数据最终会通过这个函数写入 JS
var napiCreateDouble = Module.findExportByName("libace_napi.z.so",
    "napi_create_double");
if (napiCreateDouble) {
    console.log("[+] napi_create_double found @ " + napiCreateDouble);
}

// 检查 napi_resolve_deferred — Promise resolve 入口
var napiResolve = Module.findExportByName("libace_napi.z.so",
    "napi_resolve_deferred");
if (napiResolve) {
    console.log("[+] napi_resolve_deferred found @ " + napiResolve);
}

// ============================================================
// 阶段 6: 设备端文件系统侦察
// ============================================================

console.log("\n[*] === Phase 6: Device filesystem reconnaissance ===");
console.log("[*] Run these commands manually for more info:\n");
console.log("  hdc shell \"find /system/lib64 -name '*location*' 2>/dev/null\"");
console.log("  hdc shell \"cat /proc/" + Process.id + "/maps | grep -i location\"");
console.log("  hdc shell \"ls /system/lib64/liblocation* 2>/dev/null\"");

// ============================================================
// 就绪提示
// ============================================================

console.log("\n============================================================");
console.log("  Reconnaissance ready.");
console.log("  NOW click 'Get Location (ArkTS)' in the app.");
console.log("  Watch for [CALLED]/[RETURN] messages above.");
console.log("============================================================");
