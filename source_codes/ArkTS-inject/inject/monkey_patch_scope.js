try {
    // 保存原始的 requireNapi 函数
    var origRN = globalThis.requireNapi;

    console.log("MP_H: origRN saved");

    // Hook requireNapi 函数
    globalThis.requireNapi = function(mod) {
        var r = origRN(mod);
        console.log("MP_H: requireNapi called with: " + mod);

        if (mod === "geoLocationManager" && r && typeof r.getCurrentLocation === "function") {
            console.log("MP_H: intercepted geoLocationManager!");

            var origGCL = r.getCurrentLocation;

            // 创建浅拷贝对象（绕过 frozen）
            var hooked = {};

            // 复制所有可枚举 + 不可枚举属性
            Object.getOwnPropertyNames(r).forEach(function(k) {
                try {
                    hooked[k] = r[k];
                    console.log("MP_H: copied property: " + k);
                } catch(e) {
                    console.log("MP_H: failed to copy property " + k + ": " + e.message);
                }
            });

            // 替换 getCurrentLocation
            hooked.getCurrentLocation = function(req) {
                console.log("MP_H: getCurrentLocation called!");
                return origGCL.call(r, req).then(function(loc) {
                    if (loc) {
                        loc.latitude = 666.66;
                        loc.longitude = 888.88;
                        console.log("MP_H: location patched!");
                    }
                    return loc;
                });
            };

            console.log("MP_H: hooked object created!");
            return hooked;
        }

        return r;
    };

    console.log("MP_H: requireNapi hooked successfully!");

    // 设置标记表示注入成功
    globalThis.__GEO_HOOKED = 1;

} catch(e) {
    console.log("MP_H_ERR: " + e.message);
    globalThis.__GEO_ERR = e.message;
}