#include "napi/native_api.h"
#include "LocationKit/oh_location.h"
#include "LocationKit/oh_location_type.h"
#include "hilog/log.h"
#include <cstdio>
#include <cstring>
#include <mutex>

#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0x0000
#define LOG_TAG "NAPI_HOOK"

// ---- 原始 Add 函数 ----

static napi_value Add(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value args[2] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    napi_valuetype valuetype0;
    napi_typeof(env, args[0], &valuetype0);

    napi_valuetype valuetype1;
    napi_typeof(env, args[1], &valuetype1);

    double value0;
    napi_get_value_double(env, args[0], &value0);

    double value1;
    napi_get_value_double(env, args[1], &value1);

    napi_value sum;
    napi_create_double(env, value0 + value1, &sum);
    return sum;
}

// ========== Location NAPI (Promise 模式) ==========

struct LocationCallbackCtx {
    napi_env env;
    napi_deferred deferred;
    Location_RequestConfig *requestConfig;
    napi_threadsafe_function tsfn;
    bool resolved;
    std::mutex mutex;
};

struct LocationResult {
    double latitude;
    double longitude;
    double altitude;
    double accuracy;
    double speed;
    double direction;
    int64_t timeForFix;
    int64_t timeSinceBoot;
    int32_t sourceType;
    int32_t errorCode; // 0 = success
    LocationCallbackCtx *ctx;
};

// JS 线程回调：resolve/reject Promise
static void CallJs(napi_env env, napi_value js_cb, void *context, void *data)
{
    if (env == nullptr || data == nullptr) {
        return;
    }

    auto *result = static_cast<LocationResult *>(data);
    auto *ctx = result->ctx;

    if (result->errorCode != 0) {
        napi_value errCode;
        napi_create_int32(env, result->errorCode, &errCode);

        char errorMsg[128];
        snprintf(errorMsg, sizeof(errorMsg), "StartLocating failed with code: %d", result->errorCode);
        napi_value errMsg;
        napi_create_string_utf8(env, errorMsg, NAPI_AUTO_LENGTH, &errMsg);

        napi_value errorObj;
        napi_create_object(env, &errorObj);
        napi_set_named_property(env, errorObj, "code", errCode);
        napi_set_named_property(env, errorObj, "message", errMsg);

        napi_reject_deferred(env, ctx->deferred, errorObj);
    } else {
        napi_value obj;
        napi_create_object(env, &obj);

        napi_value latitude;
        napi_create_double(env, result->latitude, &latitude);
        napi_set_named_property(env, obj, "latitude", latitude);

        napi_value longitude;
        napi_create_double(env, result->longitude, &longitude);
        napi_set_named_property(env, obj, "longitude", longitude);

        napi_value altitude;
        napi_create_double(env, result->altitude, &altitude);
        napi_set_named_property(env, obj, "altitude", altitude);

        napi_value accuracy;
        napi_create_double(env, result->accuracy, &accuracy);
        napi_set_named_property(env, obj, "accuracy", accuracy);

        napi_value speed;
        napi_create_double(env, result->speed, &speed);
        napi_set_named_property(env, obj, "speed", speed);

        napi_value direction;
        napi_create_double(env, result->direction, &direction);
        napi_set_named_property(env, obj, "direction", direction);

        napi_value timeForFix;
        napi_create_int64(env, result->timeForFix, &timeForFix);
        napi_set_named_property(env, obj, "timeForFix", timeForFix);

        napi_value timeSinceBoot;
        napi_create_int64(env, result->timeSinceBoot, &timeSinceBoot);
        napi_set_named_property(env, obj, "timeSinceBoot", timeSinceBoot);

        napi_value sourceType;
        napi_create_int32(env, result->sourceType, &sourceType);
        napi_set_named_property(env, obj, "sourceType", sourceType);

        napi_resolve_deferred(env, ctx->deferred, obj);
    }

    napi_release_threadsafe_function(ctx->tsfn, napi_tsfn_release);

    if (ctx->requestConfig != nullptr) {
        OH_Location_DestroyRequestConfig(ctx->requestConfig);
    }
    delete result;
    delete ctx;
}

// C 层位置回调（运行在 Location 服务线程）
static void OnLocationUpdate(Location_Info *location, void *userData)
{
    if (userData == nullptr || location == nullptr) {
        return;
    }

    auto *ctx = static_cast<LocationCallbackCtx *>(userData);

    {
        std::lock_guard<std::mutex> lock(ctx->mutex);
        if (ctx->resolved) {
            return;
        }
        ctx->resolved = true;
    }

    if (ctx->requestConfig != nullptr) {
        OH_Location_StopLocating(ctx->requestConfig);
    }

    Location_BasicInfo basicInfo = OH_LocationInfo_GetBasicInfo(location);

    auto *result = new LocationResult();
    result->latitude = basicInfo.latitude;
    result->longitude = basicInfo.longitude;
    result->altitude = basicInfo.altitude;
    result->accuracy = basicInfo.accuracy;
    result->speed = basicInfo.speed;
    result->direction = basicInfo.direction;
    result->timeForFix = basicInfo.timeForFix;
    result->timeSinceBoot = basicInfo.timeSinceBoot;
    result->sourceType = static_cast<int32_t>(basicInfo.locationSourceType);
    result->errorCode = 0;
    result->ctx = ctx;

    napi_acquire_threadsafe_function(ctx->tsfn);
    napi_call_threadsafe_function(ctx->tsfn, result, napi_tsfn_nonblocking);
}

// NAPI: isLocationEnabled() -> boolean
static napi_value NativeIsLocationEnabled(napi_env env, napi_callback_info info)
{
    bool enabled = false;
    Location_ResultCode resultCode = OH_Location_IsLocatingEnabled(&enabled);

    napi_value result;
    if (resultCode != LOCATION_SUCCESS) {
        napi_get_boolean(env, false, &result);
    } else {
        napi_get_boolean(env, enabled, &result);
    }
    return result;
}

// NAPI: getCurrentLocation() -> Promise<object>
static napi_value NativeGetCurrentLocation(napi_env env, napi_callback_info info)
{
    napi_deferred deferred;
    napi_value promise;
    napi_create_promise(env, &deferred, &promise);

    Location_RequestConfig *requestConfig = OH_Location_CreateRequestConfig();
    if (requestConfig == nullptr) {
        napi_value errMsg;
        napi_create_string_utf8(env, "Failed to create request config", NAPI_AUTO_LENGTH, &errMsg);
        napi_reject_deferred(env, deferred, errMsg);
        return promise;
    }

    OH_LocationRequestConfig_SetPowerConsumptionScene(requestConfig, LOCATION_LOW_POWER_CONSUMPTION);
    OH_LocationRequestConfig_SetInterval(requestConfig, 1);

    auto *ctx = new LocationCallbackCtx();
    ctx->env = env;
    ctx->deferred = deferred;
    ctx->requestConfig = requestConfig;
    ctx->resolved = false;

    napi_value workName;
    napi_create_string_utf8(env, "LocationCallback", NAPI_AUTO_LENGTH, &workName);

    napi_create_threadsafe_function(env, nullptr, nullptr, workName, 0, 1, nullptr, nullptr, nullptr, CallJs,
                                    &ctx->tsfn);

    OH_LocationRequestConfig_SetCallback(requestConfig, OnLocationUpdate, ctx);

    Location_ResultCode resultCode = OH_Location_StartLocating(requestConfig);
    if (resultCode != LOCATION_SUCCESS) {
        auto *errResult = new LocationResult();
        errResult->errorCode = static_cast<int32_t>(resultCode);
        errResult->ctx = ctx;
        napi_call_threadsafe_function(ctx->tsfn, errResult, napi_tsfn_nonblocking);
        return promise;
    }

    return promise;
}

// ---- 模块注册 ----

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        {"add", nullptr, Add, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"nativeIsLocationEnabled", nullptr, NativeIsLocationEnabled, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"nativeGetCurrentLocation", nullptr, NativeGetCurrentLocation, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module demoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "entry",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterEntryModule(void)
{
    napi_module_register(&demoModule);
}
