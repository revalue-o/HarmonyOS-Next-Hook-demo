import { hilog } from '@kit.PerformanceAnalysisKit';
import { LocationUtil, LocationData } from '../utils/LocationUtil';
import { NativeLocationUtil, NativeLocationResult } from '../utils/NativeLocationUtil';
import { abilityAccessCtrl, Permissions, Context } from '@kit.AbilityKit';
import { geoLocationManager } from '@kit.LocationKit';

const DOMAIN = 0x0000;

interface LocationRecord {
  id: number;
  timestamp: number;
  data: LocationData | NativeLocationResult;
  source: string; // 'arkts' 或 'native'
}

@Entry
@Component
struct Index {
  @State locationRecords: LocationRecord[] = [];
  @State isLoading: boolean = false;
  @State isNativeLoading: boolean = false;
  @State errorMessage: string = '';
  @State hasPermission: boolean = false;
  private recordCounter: number = 0;
  private abilityContext: Context | null = null;

  aboutToAppear(): void {
    const hostContext = this.getUIContext().getHostContext();
    if (hostContext) {
      this.abilityContext = hostContext;
      LocationUtil.init(hostContext);
    }
    this.checkPermission();
  }

  private async checkPermission(): Promise<void> {
    try {
      const hasPermission = await LocationUtil.checkLocationPermissions();
      this.hasPermission = hasPermission;
      hilog.info(DOMAIN, 'Index', 'Has location permission: %{public}s', hasPermission.toString());
    } catch (err) {
      hilog.error(DOMAIN, 'Index', 'Check permission failed: %{public}s', JSON.stringify(err));
    }
  }

  private async requestPermission(): Promise<void> {
    try {
      if (!this.abilityContext) {
        this.errorMessage = '应用上下文未初始化';
        return;
      }

      const atManager = abilityAccessCtrl.createAtManager();
      const permissions: Array<Permissions> = [
        'ohos.permission.APPROXIMATELY_LOCATION',
        'ohos.permission.LOCATION'
      ];

      hilog.info(DOMAIN, 'Index', 'Requesting location permissions...');

      const result = await atManager.requestPermissionsFromUser(this.abilityContext, permissions);

      const granted = result.authResults.some((status: number) =>
        status === abilityAccessCtrl.GrantStatus.PERMISSION_GRANTED
      );

      this.hasPermission = granted;

      if (!granted) {
        this.errorMessage = '位置权限被拒绝，请在设置中开启权限';
      }

      hilog.info(DOMAIN, 'Index', 'Permission request result: %{public}s', granted.toString());
    } catch (err) {
      this.errorMessage = '请求权限失败: ' + JSON.stringify(err);
      hilog.error(DOMAIN, 'Index', 'Request permission failed: %{public}s', JSON.stringify(err));
    }
  }

  /**
   * ArkTS 层获取位置
   */
  private async getLocation(): Promise<void> {
    if (!this.hasPermission) {
      await this.requestPermission();
      if (!this.hasPermission) {
        return;
      }
    }

    const isLocationEnabled = await LocationUtil.isLocationEnabled();
    if (!isLocationEnabled) {
      this.errorMessage = '位置服务未开启，请在设置中开启位置服务';
      return;
    }

    this.isLoading = true;
    this.errorMessage = '';

    try {
      const request: geoLocationManager.LocationRequest = {
        priority: geoLocationManager.LocationRequestPriority.LOW_POWER
      };

      const locationData = await LocationUtil.getCurrentLocation(request);

      if (locationData) {
        this.recordCounter++;
        this.locationRecords = [{
          id: this.recordCounter,
          timestamp: Date.now(),
          data: locationData,
          source: 'arkts'
        }, ...this.locationRecords];

        hilog.info(DOMAIN, 'Index', 'ArkTS Location obtained: %{public}s', JSON.stringify(locationData));
      } else {
        this.errorMessage = '获取位置失败，请检查位置服务是否开启';
      }
    } catch (err) {
      this.errorMessage = '获取位置异常: ' + JSON.stringify(err);
      hilog.error(DOMAIN, 'Index', 'Get location failed: %{public}s', JSON.stringify(err));
    } finally {
      this.isLoading = false;
    }
  }

  /**
   * Native 层获取位置
   */
  private async getNativeLocation(): Promise<void> {
    if (!this.hasPermission) {
      await this.requestPermission();
      if (!this.hasPermission) {
        return;
      }
    }

    const isEnabled = NativeLocationUtil.isLocationEnabled();
    if (!isEnabled) {
      this.errorMessage = '位置服务未开启 (Native检测)，请在设置中开启位置服务';
      return;
    }

    this.isNativeLoading = true;
    this.errorMessage = '';

    try {
      const locationData = await NativeLocationUtil.getCurrentLocation();

      if (locationData) {
        this.recordCounter++;
        this.locationRecords = [{
          id: this.recordCounter,
          timestamp: Date.now(),
          data: locationData,
          source: 'native'
        }, ...this.locationRecords];

        hilog.info(DOMAIN, 'Index', 'Native Location obtained: %{public}s', JSON.stringify(locationData));
      } else {
        this.errorMessage = 'Native获取位置失败';
      }
    } catch (err) {
      this.errorMessage = 'Native获取位置异常: ' + JSON.stringify(err);
      hilog.error(DOMAIN, 'Index', 'Native get location failed: %{public}s', JSON.stringify(err));
    } finally {
      this.isNativeLoading = false;
    }
  }

  private clearRecords(): void {
    this.locationRecords = [];
    this.errorMessage = '';
    this.recordCounter = 0;
  }

  build() {
    Column() {
      // 标题栏
      Row() {
        Text('位置信息获取器')
          .fontSize(24)
          .fontWeight(FontWeight.Bold)
          .fontColor('#333333')
      }
      .width('100%')
      .height(60)
      .justifyContent(FlexAlign.Center)
      .backgroundColor('#F5F5F5')
      .borderRadius({ topLeft: 16, topRight: 16 })

      // 权限状态提示
      if (!this.hasPermission) {
        Row() {
          Text('需要位置权限才能使用')
            .fontSize(14)
            .fontColor('#FF6B6B')
            .margin({ right: 12 })
          Button('授予权限')
            .fontSize(14)
            .backgroundColor('#4CAF50')
            .onClick(() => {
              this.requestPermission();
            })
        }
        .width('100%')
        .padding(12)
        .backgroundColor('#FFF5F5')
        .margin({ top: 12, left: 16, right: 16 })
        .borderRadius(8)
      }

      // ArkTS 层按钮
      Row() {
        Button('获取位置 (ArkTS)')
          .fontSize(14)
          .fontWeight(FontWeight.Medium)
          .backgroundColor('#2196F3')
          .fontColor(Color.White)
          .borderRadius(8)
          .padding({ left: 16, right: 16, top: 10, bottom: 10 })
          .enabled(!this.isLoading)
          .onClick(() => {
            this.getLocation();
          })

        Button('获取位置 (Native)')
          .fontSize(14)
          .fontWeight(FontWeight.Medium)
          .backgroundColor('#FF9800')
          .fontColor(Color.White)
          .borderRadius(8)
          .padding({ left: 16, right: 16, top: 10, bottom: 10 })
          .enabled(!this.isNativeLoading)
          .onClick(() => {
            this.getNativeLocation();
          })

        if (this.locationRecords.length > 0) {
          Button('清空')
            .fontSize(14)
            .fontWeight(FontWeight.Medium)
            .backgroundColor('#F44336')
            .fontColor(Color.White)
            .borderRadius(8)
            .padding({ left: 16, right: 16, top: 10, bottom: 10 })
            .enabled(!this.isLoading && !this.isNativeLoading)
            .onClick(() => {
              this.clearRecords();
            })
        }
      }
      .width('100%')
      .justifyContent(FlexAlign.Center)
      .margin({ top: 16 })

      // 加载状态
      if (this.isLoading) {
        Row() {
          LoadingProgress()
            .width(24)
            .height(24)
            .color('#2196F3')
          Text('ArkTS 正在获取位置...')
            .fontSize(14)
            .fontColor('#666666')
            .margin({ left: 12 })
        }
        .width('100%')
        .justifyContent(FlexAlign.Center)
        .margin({ top: 16 })
      }

      if (this.isNativeLoading) {
        Row() {
          LoadingProgress()
            .width(24)
            .height(24)
            .color('#FF9800')
          Text('Native 正在获取位置...')
            .fontSize(14)
            .fontColor('#666666')
            .margin({ left: 12 })
        }
        .width('100%')
        .justifyContent(FlexAlign.Center)
        .margin({ top: 16 })
      }

      // 错误信息
      if (this.errorMessage) {
        Text(this.errorMessage)
          .fontSize(14)
          .fontColor('#F44336')
          .width('100%')
          .textAlign(TextAlign.Center)
          .margin({ top: 12, left: 16, right: 16 })
          .padding(12)
          .backgroundColor('#FFF5F5')
          .borderRadius(8)
      }

      // 记录数量
      if (this.locationRecords.length > 0) {
        Text(`共 ${this.locationRecords.length} 条记录`)
          .fontSize(12)
          .fontColor('#999999')
          .width('100%')
          .textAlign(TextAlign.Center)
          .margin({ top: 12 })
      }

      // 位置记录列表
      if (this.locationRecords.length > 0) {
        List({ space: 12 }) {
          ForEach(this.locationRecords, (record: LocationRecord) => {
            ListItem() {
              this.LocationRecordCard(record)
            }
          }, (record: LocationRecord) => record.id.toString())
        }
        .width('100%')
        .layoutWeight(1)
        .margin({ top: 12, left: 16, right: 16, bottom: 16 })
        .scrollBar(BarState.Auto)
        .edgeEffect(EdgeEffect.Spring)
      } else {
        Column() {
          Text('点击上方按钮获取位置信息')
            .fontSize(16)
            .fontColor('#999999')
        }
        .width('100%')
        .layoutWeight(1)
        .justifyContent(FlexAlign.Center)
      }
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#FAFAFA')
  }

  @Builder
  LocationRecordCard(record: LocationRecord) {
    Column() {
      Row() {
        Text(`记录 #${record.id}`)
          .fontSize(16)
          .fontWeight(FontWeight.Bold)
          .fontColor('#333333')

        // 来源标签
        Text(record.source === 'native' ? 'Native' : 'ArkTS')
          .fontSize(11)
          .fontColor(Color.White)
          .backgroundColor(record.source === 'native' ? '#FF9800' : '#2196F3')
          .borderRadius(4)
          .padding({ left: 6, right: 6, top: 2, bottom: 2 })
          .margin({ left: 8 })

        Blank()

        Text(new Date(record.timestamp).toLocaleString('zh-CN'))
          .fontSize(12)
          .fontColor('#999999')
      }
      .width('100%')
      .margin({ bottom: 12 })

      Scroll() {
        Text(JSON.stringify(record.data, null, 2))
          .fontSize(12)
          .fontColor('#333333')
          .fontFamily('monospace')
          .width('100%')
      }
      .width('100%')
      .height(200)
      .scrollBar(BarState.Auto)
      .backgroundColor('#F8F8F8')
      .borderRadius(8)
      .padding(12)
    }
    .width('100%')
    .padding(16)
    .backgroundColor(Color.White)
    .borderRadius(12)
    .shadow({
      radius: 8,
      color: '#1A000000',
      offsetX: 0,
      offsetY: 2
    })
  }
}
