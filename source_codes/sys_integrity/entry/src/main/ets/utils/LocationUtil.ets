import { Context } from '@kit.AbilityKit';
import { abilityAccessCtrl, Permissions } from '@kit.AbilityKit';
import { geoLocationManager } from '@kit.LocationKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';

const DOMAIN = 0x0000;

/**
 * 位置数据接口
 */
export interface LocationData {
  latitude: number;
  longitude: number;
  altitude: number;
  accuracy: number;
  speed: number;
  timeStamp: number;
  direction: number;
}

/**
 * 位置工具类
 */
export class LocationUtil {
  private static context: Context | null = null;
  private static atManager: abilityAccessCtrl.AtManager = abilityAccessCtrl.createAtManager();

  /**
   * 初始化位置服务
   */
  static init(context: Context): void {
    LocationUtil.context = context;
    hilog.info(DOMAIN, 'LocationUtil', 'Initialized with context');
  }

  /**
   * 检查位置权限
   */
  static async checkLocationPermissions(): Promise<boolean> {
    try {
      if (!LocationUtil.context) {
        hilog.error(DOMAIN, 'LocationUtil', 'Context not initialized');
        return false;
      }

      const permissions: Array<Permissions> = ['ohos.permission.LOCATION'];
      const bundleInfo = LocationUtil.context.applicationInfo;

      const grantStatus = await LocationUtil.atManager.checkAccessToken(
        bundleInfo.accessTokenId,
        permissions[0]
      );

      const hasPermission = grantStatus === abilityAccessCtrl.GrantStatus.PERMISSION_GRANTED;

      hilog.info(DOMAIN, 'LocationUtil', 'Has location permission: %{public}s', hasPermission.toString());
      return hasPermission;
    } catch (err) {
      const error = err as BusinessError;
      hilog.error(DOMAIN, 'LocationUtil', 'Check permission failed: %{public}s', JSON.stringify(error));
      return false;
    }
  }

  /**
   * 请求位置权限
   */
  static async requestLocationPermissions(): Promise<boolean> {
    try {
      if (!LocationUtil.context) {
        hilog.error(DOMAIN, 'LocationUtil', 'Context not initialized');
        return false;
      }

      const permissions: Array<Permissions> = ['ohos.permission.LOCATION'];

      hilog.info(DOMAIN, 'LocationUtil', 'Requesting location permissions...');

      const result = await LocationUtil.atManager.requestPermissionsFromUser(
        LocationUtil.context,
        permissions
      );

      // 检查权限是否被授予
      const granted = result.authResults[0] === abilityAccessCtrl.GrantStatus.PERMISSION_GRANTED;

      if (granted) {
        hilog.info(DOMAIN, 'LocationUtil', 'Location permissions granted');
        return true;
      } else {
        hilog.warn(DOMAIN, 'LocationUtil', 'Location permissions denied');
        return false;
      }
    } catch (err) {
      const error = err as BusinessError;
      hilog.error(DOMAIN, 'LocationUtil', 'Request permissions failed: %{public}s', JSON.stringify(error));
      return false;
    }
  }

  /**
   * 获取当前位置
   */
  static async getCurrentLocation(request: geoLocationManager.LocationRequest): Promise<LocationData | null> {
    try {
      if (!LocationUtil.context) {
        hilog.error(DOMAIN, 'LocationUtil', 'Context not initialized');
        return null;
      }

      hilog.info(DOMAIN, 'LocationUtil', 'Getting current location...');

      // 获取位置
      const location = await geoLocationManager.getCurrentLocation(request);

      if (!location) {
        hilog.error(DOMAIN, 'LocationUtil', 'Failed to get location, result is null');
        return null;
      }

      // 构建位置数据 - 只包含 Location 类型实际拥有的字段
      const locationData: LocationData = {
        latitude: location.latitude,
        longitude: location.longitude,
        altitude: location.altitude,
        accuracy: location.accuracy,
        speed: location.speed,
        timeStamp: location.timeStamp,
        direction: location.direction
      };

      hilog.info(DOMAIN, 'LocationUtil', 'Location obtained: lat=%{public}f, lon=%{public}f',
        locationData.latitude, locationData.longitude);

      return locationData;
    } catch (err) {
      const error = err as BusinessError;
      hilog.error(DOMAIN, 'LocationUtil', 'Get location failed: %{public}s', JSON.stringify(error));
      return null;
    }
  }

  /**
   * 检查位置服务是否启用
   */
  static async isLocationEnabled(): Promise<boolean> {
    try {
      const isEnabled = await geoLocationManager.isLocationEnabled();
      hilog.info(DOMAIN, 'LocationUtil', 'Location service enabled: %{public}s', isEnabled.toString());
      return isEnabled;
    } catch (err) {
      const error = err as BusinessError;
      hilog.error(DOMAIN, 'LocationUtil', 'Check location enabled failed: %{public}s', JSON.stringify(error));
      return false;
    }
  }

  /**
   * 格式化位置数据为JSON字符串
   */
  static formatLocationToString(data: LocationData): string {
    return JSON.stringify(data, null, 2);
  }

  /**
   * 获取位置优先级描述
   */
  static getPriorityDescription(priority: number): string {
    switch (priority) {
      case geoLocationManager.LocationRequestPriority.LOW_POWER:
        return '低功耗';
      case geoLocationManager.LocationRequestPriority.FIRST_FIX:
        return '快速定位';
      case geoLocationManager.LocationRequestPriority.ACCURACY:
        return '高精度';
      default:
        return '未知';
    }
  }
}
