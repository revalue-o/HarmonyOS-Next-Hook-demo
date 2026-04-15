import { hilog } from '@kit.PerformanceAnalysisKit';
import { nativeIsLocationEnabled, nativeGetCurrentLocation, NativeLocationData } from 'libentry.so';

const DOMAIN = 0x0000;

/**
 * Native 层位置数据接口（与 ArkTS 层 LocationData 兼容）
 */
export interface NativeLocationResult {
  latitude: number;
  longitude: number;
  altitude: number;
  accuracy: number;
  speed: number;
  direction: number;
  timeForFix: number;
  timeSinceBoot: number;
  sourceType: number;
}

/**
 * Native 层位置工具类
 * 通过 NAPI 调用 C++ 层的 OH_Location_* API (since API 13)
 */
export class NativeLocationUtil {

  /**
   * 检查位置服务是否启用（Native 层同步调用）
   */
  static isLocationEnabled(): boolean {
    try {
      const enabled = nativeIsLocationEnabled();
      hilog.info(DOMAIN, 'NativeLocationUtil', 'Location enabled (native): %{public}s', enabled.toString());
      return enabled;
    } catch (err) {
      hilog.error(DOMAIN, 'NativeLocationUtil', 'Check location enabled failed: %{public}s', JSON.stringify(err));
      return false;
    }
  }

  /**
   * 获取当前位置（Native 层异步调用）
   * 通过 Promise 返回位置数据
   */
  static async getCurrentLocation(): Promise<NativeLocationResult | null> {
    try {
      hilog.info(DOMAIN, 'NativeLocationUtil', 'Getting current location via native API...');

      const data: NativeLocationData = await nativeGetCurrentLocation();

      if (data) {
        hilog.info(DOMAIN, 'NativeLocationUtil',
          'Native location obtained: lat=%{public}f, lon=%{public}f, source=%{public}d',
          data.latitude, data.longitude, data.sourceType);
        return data;
      } else {
        hilog.error(DOMAIN, 'NativeLocationUtil', 'Native location result is null');
        return null;
      }
    } catch (err) {
      hilog.error(DOMAIN, 'NativeLocationUtil', 'Native get location failed: %{public}s', JSON.stringify(err));
      return null;
    }
  }
}
