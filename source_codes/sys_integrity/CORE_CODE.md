# StarShield 核心代码文档

## 项目概述

这是一个HarmonyOS应用，用于测试华为设备安全API和位置API。主要功能包括：
- 位置信息获取（需要LocationUtil.ets支持）
- 系统完整性检测（越狱、模拟器、攻击检测）

---

## 1. SecurityCheckUtil.ets

**文件路径**: `entry/src/main/ets/utils/SecurityCheckUtil.ets`

**功能**: 设备安全检测工具类，集成华为Device Security Kit的系统完整性检测API

**核心功能**:
- 系统完整性检测（checkSysIntegrity）
- JWS格式响应解析
- Base64解码实现
- Nonce随机数生成

```typescript
import { BusinessError } from '@kit.BasicServicesKit';
import { Context } from '@kit.AbilityKit';
import { safetyDetect } from '@kit.DeviceSecurityKit';

/**
 * 系统完整性检测结果接口
 */
export interface SysIntegrityResult {
  timestamp: string;
  success: boolean;
  resultJson?: string;
  error?: string;
  details?: IntegrityDetails;
  jwsResult?: JWSResult;
}

/**
 * JWS解析结果接口
 */
export interface JWSResult {
  header: string;
  payload: SysIntegrityPayload;
  signature: string;
}

/**
 * 完整性详情接口
 */
export interface IntegrityDetails {
  isJailBreak?: boolean;
  isEmulator?: boolean;
  isAttack?: boolean;
  riskLevel?: string;
  basicIntegrity?: boolean;
  appId?: string;
  hapBundleName?: string;
  hapCertificateSha256?: string;
}

/**
 * 系统完整性检测详情接口
 */
export interface SysIntegrityDetail {
  jailbreak?: boolean;
  emulator?: boolean;
  attack?: boolean;
}

/**
 * 系统完整性JWS负载接口
 */
export interface SysIntegrityPayload {
  nonce: string;
  timestamp: number;
  hapBundleName: string;
  hapCertificateSha256?: string;
  basicIntegrity: boolean;
  appId: string;
  detail?: SysIntegrityDetail;
}

/**
 * 系统完整性请求接口
 */
export interface SysIntegrityRequest {
  nonce: string;
}

/**
 * 设备安全检测工具类
 */
export class SecurityCheckUtil {
  private static context: Context | null = null;

  /**
   * 初始化安全检测服务
   */
  static init(context: Context): void {
    SecurityCheckUtil.context = context;
    console.log('[SecurityCheckUtil] Initialized with context');
  }

  /**
   * 生成随机nonce（16-66字节的base64编码值）
   * 使用Math.random()生成伪随机数
   */
  private static generateNonce(): string {
    // 生成32字节的随机字符串（符合16-66字节要求）
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let result = '';

    // 使用 Math.random() 生成伪随机数
    for (let i = 0; i < 32; i++) {
      const randomValue = Math.floor(Math.random() * chars.length);
      // 使用 charAt() 代替索引访问（ArkTS要求）
      result += chars.charAt(randomValue);
    }

    console.log('[SecurityCheckUtil] Generated nonce length:', result.length);
    return result;
  }

  /**
   * 手动实现Base64解码
   */
  private static base64Decode(base64Str: string): string {
    try {
      // 处理Base64URL编码
      let str = base64Str.replace(/-/g, '+').replace(/_/g, '/');

      // 补齐padding
      while (str.length % 4 !== 0) {
        str += '=';
      }

      // 手动实现Base64解码
      const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      let result = '';
      let buffer = 0;
      let bits = 0;

      for (let i = 0; i < str.length; i++) {
        const char = str.charAt(i);  // 使用 charAt() 代替索引访问
        if (char === '=') break;

        const index = base64Chars.indexOf(char);
        if (index === -1) continue;

        buffer = (buffer << 6) | index;
        bits += 6;

        if (bits >= 8) {
          bits -= 8;
          result += String.fromCharCode((buffer >> bits) & 0xFF);
        }
      }

      return result;
    } catch (err) {
      console.error('[SecurityCheckUtil] Base64 decode failed:', JSON.stringify(err));
      return '';
    }
  }

  /**
   * 解析JWS格式的响应
   * JWS格式：header.payload.signature（三部分通过"."连接）
   */
  private static parseJWS(jwsString: string): JWSResult | null {
    try {
      console.log('[SecurityCheckUtil] Parsing JWS, length:', jwsString.length);

      const parts = jwsString.split('.');
      if (parts.length !== 3) {
        console.error('[SecurityCheckUtil] Invalid JWS format, expected 3 parts, got:', parts.length);
        return null;
      }

      // 使用数组解构代替索引访问
      const partArray: string[] = Array.from(parts);
      const headerEncoded = partArray[0];
      const payloadEncoded = partArray[1];
      const signature = partArray[2];

      // 解码payload - 使用类名调用
      const decodedPayload = SecurityCheckUtil.base64Decode(payloadEncoded);
      const payload = JSON.parse(decodedPayload) as SysIntegrityPayload;

      console.log('[SecurityCheckUtil] JWS payload parsed successfully');
      console.log('[SecurityCheckUtil] basicIntegrity:', payload.basicIntegrity);

      const result: JWSResult = {
        header: headerEncoded,
        payload: payload,
        signature: signature
      };

      return result;
    } catch (err) {
      console.error('[SecurityCheckUtil] Failed to parse JWS:', JSON.stringify(err));
      return null;
    }
  }

  /**
   * 检测系统完整性
   * 检测设备环境安全状态，包括越狱检测、模拟器检测、攻击检测等
   */
  static async checkSystemIntegrity(): Promise<SysIntegrityResult> {
    if (!SecurityCheckUtil.context) {
      console.error('[SecurityCheckUtil] Context not initialized');
      return {
        timestamp: new Date().toISOString(),
        success: false,
        error: 'Context not initialized'
      };
    }

    try {
      console.log('[SecurityCheckUtil] Starting system integrity check');

      // 生成随机nonce
      const nonce = SecurityCheckUtil.generateNonce();

      // 构建请求 - 添加类型注解
      const request: SysIntegrityRequest = {
        nonce: nonce
      };

      console.log('[SecurityCheckUtil] Sending request with nonce length:', nonce.length);

      // 调用华为safetyDetect的checkSysIntegrity接口
      const response = await safetyDetect.checkSysIntegrity(request);

      if (response && response.result) {
        // 解析JWS响应
        const jwsParsed = SecurityCheckUtil.parseJWS(response.result);

        if (!jwsParsed) {
          return {
            timestamp: new Date().toISOString(),
            success: false,
            error: 'Failed to parse JWS response',
            resultJson: response.result
          };
        }

        // 构建完整性详情
        const integrityDetails: IntegrityDetails = {
          isJailBreak: jwsParsed.payload.detail?.jailbreak,
          isEmulator: jwsParsed.payload.detail?.emulator,
          isAttack: jwsParsed.payload.detail?.attack,
          basicIntegrity: jwsParsed.payload.basicIntegrity,
          appId: jwsParsed.payload.appId,
          hapBundleName: jwsParsed.payload.hapBundleName,
          hapCertificateSha256: jwsParsed.payload.hapCertificateSha256,
          riskLevel: jwsParsed.payload.basicIntegrity ? 'low' : 'high'
        };

        const result: SysIntegrityResult = {
          timestamp: new Date().toISOString(),
          success: true,
          resultJson: response.result,
          details: integrityDetails,
          jwsResult: jwsParsed
        };

        console.log('[SecurityCheckUtil] System integrity check completed successfully');
        return result;
      } else {
        return {
          timestamp: new Date().toISOString(),
          success: false,
          error: 'No result returned from API'
        };
      }

    } catch (err) {
      const error = err as BusinessError;
      console.error('[SecurityCheckUtil] System integrity check failed:', error.code, error.message);

      return {
        timestamp: new Date().toISOString(),
        success: false,
        error: 'Error code: ' + error.code + ', Message: ' + error.message
      };
    }
  }

  /**
   * 获取支持的安全检测类型
   */
  static getSupportedCheckTypes(): string[] {
    return [
      '系统完整性检测 (checkSysIntegrity)'
    ];
  }

  /**
   * 获取系统完整性检测的说明
   */
  static getSysIntegrityDescription(): string {
    return '系统完整性检测用于检测设备环境的安全状态，包括：\n' +
           '- 越狱检测 (jailbreak)\n' +
           '- 模拟器检测 (emulator)\n' +
           '- 攻击检测 (attack)\n' +
           '- 风险等级评估 (basicIntegrity)';
  }
}
```

---

## 2. Index.ets

**文件路径**: `entry/src/main/ets/pages/Index.ets`

**功能**: 主UI页面，提供位置获取和安全检测功能的用户界面

**依赖**:
- LocationUtil.ets（位置工具类，需要单独实现）
- SecurityCheckUtil.ets（已包含）

**UI组件**:
- 位置权限请求
- 获取位置按钮
- 系统完整性检测按钮
- 位置记录列表展示
- 安全检测结果卡片

```typescript
import { hilog } from '@kit.PerformanceAnalysisKit';
import { LocationUtil, LocationData } from '../utils/LocationUtil';
import { SecurityCheckUtil, SysIntegrityResult } from '../utils/SecurityCheckUtil';
import { abilityAccessCtrl } from '@kit.AbilityKit';
import { geoLocationManager } from '@kit.LocationKit';

const DOMAIN = 0x0000;

interface LocationRecord {
  id: number;
  timestamp: number;
  data: LocationData;
}

@Entry
@Component
struct Index {
  @State locationRecords: LocationRecord[] = [];
  @State isLoading: boolean = false;
  @State errorMessage: string = '';
  @State hasPermission: boolean = false;
  @State isSecurityChecking: boolean = false;
  @State sysIntegrityResult: SysIntegrityResult | null = null;
  @State securityErrorMessage: string = '';
  private recordCounter: number = 0;

  aboutToAppear(): void {
    // 初始化位置服务
    const hostContext = this.getUIContext().getHostContext();
    if (hostContext) {
      LocationUtil.init(hostContext);
      SecurityCheckUtil.init(hostContext);
    }
    this.checkPermission();
  }

  /**
   * 检查权限状态
   */
  private async checkPermission(): Promise<void> {
    try {
      const hasPermission = await LocationUtil.checkLocationPermissions();
      this.hasPermission = hasPermission;
      hilog.info(DOMAIN, 'Index', 'Has location permission: %{public}s', hasPermission.toString());
    } catch (err) {
      hilog.error(DOMAIN, 'Index', 'Check permission failed: %{public}s', JSON.stringify(err));
    }
  }

  /**
   * 请求位置权限
   */
  private async requestPermission(): Promise<void> {
    try {
      const granted = await LocationUtil.requestLocationPermissions();
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
   * 获取位置信息
   */
  private async getLocation(): Promise<void> {
    // 检查权限
    if (!this.hasPermission) {
      await this.requestPermission();
      if (!this.hasPermission) {
        return;
      }
    }

    this.isLoading = true;
    this.errorMessage = '';

    try {
      const request: geoLocationManager.LocationRequest = {
        priority: 0x001, // LOW_POWER
        maxAccuracy: 100
      };

      const locationData = await LocationUtil.getCurrentLocation(request);

      if (locationData) {
        this.recordCounter++;
        const record: LocationRecord = {
          id: this.recordCounter,
          timestamp: Date.now(),
          data: locationData
        };

        // 添加到列表开头
        this.locationRecords = [record, ...this.locationRecords];

        hilog.info(DOMAIN, 'Index', 'Location obtained: %{public}s', JSON.stringify(locationData));
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
   * 清空记录
   */
  private clearRecords(): void {
    this.locationRecords = [];
    this.errorMessage = '';
    this.recordCounter = 0;
  }

  /**
   * 执行系统完整性检测
   */
  private async performSysIntegrityCheck(): Promise<void> {
    this.isSecurityChecking = true;
    this.securityErrorMessage = '';
    this.sysIntegrityResult = null;

    try {
      const result = await SecurityCheckUtil.checkSystemIntegrity();
      this.sysIntegrityResult = result;

      if (!result.success) {
        this.securityErrorMessage = '系统完整性检测失败: ' + (result.error || '未知错误');
      }

      hilog.info(DOMAIN, 'Index', 'System integrity check completed: %{public}s', JSON.stringify(result));
    } catch (err) {
      this.securityErrorMessage = '系统完整性检测异常: ' + JSON.stringify(err);
      hilog.error(DOMAIN, 'Index', 'System integrity check failed: %{public}s', JSON.stringify(err));
    } finally {
      this.isSecurityChecking = false;
    }
  }

  /**
   * 清空安全检测结果
   */
  private clearSecurityResults(): void {
    this.sysIntegrityResult = null;
    this.securityErrorMessage = '';
  }

  build() {
    Column() {
      // 标题栏
      Row() {
        Text('🌍 位置信息获取器')
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
          Text('⚠️ 需要位置权限才能使用')
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

      // 操作按钮区
      Row() {
        Button('获取位置')
          .fontSize(16)
          .fontWeight(FontWeight.Medium)
          .backgroundColor('#2196F3')
          .fontColor(Color.White)
          .borderRadius(8)
          .padding({ left: 24, right: 24, top: 12, bottom: 12 })
          .enabled(!this.isLoading)
          .onClick(() => {
            this.getLocation();
          })

        if (this.locationRecords.length > 0) {
          Button('清空')
            .fontSize(16)
            .fontWeight(FontWeight.Medium)
            .backgroundColor('#F44336')
            .fontColor(Color.White)
            .borderRadius(8)
            .padding({ left: 24, right: 24, top: 12, bottom: 12 })
            .margin({ left: 12 })
            .enabled(!this.isLoading)
            .onClick(() => {
              this.clearRecords();
            })
        }
      }
      .width('100%')
      .justifyContent(FlexAlign.Center)
      .margin({ top: 16 })

      // 分隔线
      Divider()
        .width('90%')
        .height(1)
        .color('#E0E0E0')
        .margin({ top: 16 })

      // 安全检测标题
      Row() {
        Text('🔒 设备安全检测')
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .fontColor('#333333')
      }
      .width('100%')
      .justifyContent(FlexAlign.Center)
      .margin({ top: 16 })

      // 安全检测按钮区
      Row() {
        Button('系统完整性')
          .fontSize(14)
          .fontWeight(FontWeight.Medium)
          .backgroundColor('#9C27B0')
          .fontColor(Color.White)
          .borderRadius(8)
          .padding({ left: 16, right: 16, top: 10, bottom: 10 })
          .enabled(!this.isSecurityChecking)
          .onClick(() => {
            this.performSysIntegrityCheck();
          })

        if (this.sysIntegrityResult) {
          Button('清空')
            .fontSize(14)
            .fontWeight(FontWeight.Medium)
            .backgroundColor('#757575')
            .fontColor(Color.White)
            .borderRadius(8)
            .padding({ left: 16, right: 16, top: 10, bottom: 10 })
            .margin({ left: 8 })
            .enabled(!this.isSecurityChecking)
            .onClick(() => {
              this.clearSecurityResults();
            })
        }
      }
      .width('100%')
      .justifyContent(FlexAlign.Center)
      .margin({ top: 12 })

      // 加载状态
      if (this.isLoading) {
        Row() {
          LoadingProgress()
            .width(24)
            .height(24)
            .color('#2196F3')
          Text('正在获取位置信息...')
            .fontSize(14)
            .fontColor('#666666')
            .margin({ left: 12 })
        }
        .width('100%')
        .justifyContent(FlexAlign.Center)
        .margin({ top: 16 })
      }

      // 安全检测加载状态
      if (this.isSecurityChecking) {
        Row() {
          LoadingProgress()
            .width(24)
            .height(24)
            .color('#FF9800')
          Text('正在进行安全检测...')
            .fontSize(14)
            .fontColor('#666666')
            .margin({ left: 12 })
        }
        .width('100%')
        .justifyContent(FlexAlign.Center)
        .margin({ top: 16 })
      }

      // 安全检测错误信息
      if (this.securityErrorMessage) {
        Text(this.securityErrorMessage)
          .fontSize(14)
          .fontColor('#F44336')
          .width('100%')
          .textAlign(TextAlign.Center)
          .margin({ top: 12, left: 16, right: 16 })
          .padding(12)
          .backgroundColor('#FFF5F5')
          .borderRadius(8)
      }

      // 安全检测结果
      if (this.sysIntegrityResult) {
        this.SysIntegrityResultCard(this.sysIntegrityResult)
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

      // 位置记录列表（无尽滚动）
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
        // 空状态
        Column() {
          Text('📍')
            .fontSize(64)
            .margin({ bottom: 16 })
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

  /**
   * 位置记录卡片组件
   */
  @Builder
  LocationRecordCard(record: LocationRecord) {
    Column() {
      // 卡片头部
      Row() {
        Text(`记录 #${record.id}`)
          .fontSize(16)
          .fontWeight(FontWeight.Bold)
          .fontColor('#333333')

        Blank()

        Text(new Date(record.timestamp).toLocaleString('zh-CN'))
          .fontSize(12)
          .fontColor('#999999')
      }
      .width('100%')
      .margin({ bottom: 12 })

      // 位置数据 JSON 展示
      Scroll() {
        Text(this.formatJson(JSON.stringify(record.data, null, 2)))
          .fontSize(12)
          .fontColor('#333333')
          .fontFamily('monospace')
          .width('100%')
      }
      .width('100%')
      .height(300)
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

  /**
   * 格式化 JSON，添加颜色
   */
  private formatJson(json: string): string {
    return json;
  }

  /**
   * 系统完整性检测结果卡片
   */
  @Builder
  SysIntegrityResultCard(result: SysIntegrityResult) {
    Column() {
      // 卡片头部
      Row() {
        Text('🛡️ 系统完整性检测')
          .fontSize(16)
          .fontWeight(FontWeight.Bold)
          .fontColor('#333333')

        Blank()

        Text(result.success ? '✅ 成功' : '❌ 失败')
          .fontSize(12)
          .fontColor(result.success ? '#4CAF50' : '#F44336')
      }
      .width('100%')
      .margin({ bottom: 12 })

      // 检测时间
      Text(`检测时间: ${result.timestamp}`)
        .fontSize(12)
        .fontColor('#999999')
        .width('100%')
        .margin({ bottom: 12 })

      // 详细检测结果
      if (result.details) {
        Column() {
          // 基本完整性状态（优先显示）
          if (result.details.basicIntegrity !== undefined) {
            Row() {
              Text('系统完整性:')
                .fontSize(14)
                .fontColor('#666666')
              Blank()
              Text(result.details.basicIntegrity ? '✅ 完整' : '⚠️ 存在风险')
                .fontSize(14)
                .fontWeight(FontWeight.Medium)
                .fontColor(result.details.basicIntegrity ? '#4CAF50' : '#FF9800')
            }
            .width('100%')
            .margin({ bottom: 8 })
          }

          // 应用包名
          if (result.details.hapBundleName) {
            Row() {
              Text('应用包名:')
                .fontSize(12)
                .fontColor('#666666')
              Blank()
              Text(result.details.hapBundleName)
                .fontSize(12)
                .fontColor('#333333')
                .maxLines(1)
                .textOverflow({ overflow: TextOverflow.Ellipsis })
            }
            .width('100%')
            .margin({ bottom: 8 })
          }

          // 应用ID
          if (result.details.appId) {
            Row() {
              Text('应用ID:')
                .fontSize(12)
                .fontColor('#666666')
              Blank()
              Text(result.details.appId)
                .fontSize(12)
                .fontColor('#333333')
                .maxLines(1)
                .textOverflow({ overflow: TextOverflow.Ellipsis })
            }
            .width('100%')
            .margin({ bottom: 8 })
          }

          // 证书SHA256
          if (result.details.hapCertificateSha256) {
            Row() {
              Text('证书SHA256:')
                .fontSize(12)
                .fontColor('#666666')
              Blank()
              Text(result.details.hapCertificateSha256.substring(0, 16) + '...')
                .fontSize(10)
                .fontColor('#333333')
                .fontFamily('monospace')
            }
            .width('100%')
            .margin({ bottom: 8 })
          }

          // 分隔线
          Divider()
            .width('100%')
            .height(1)
            .color('#E0E0E0')
            .margin({ top: 8, bottom: 8 })

          // 越狱检测
          Row() {
            Text('越狱检测:')
              .fontSize(14)
              .fontColor('#666666')
            Blank()
            Text(result.details.isJailBreak === true ? '⚠️ 检测到越狱' :
                  result.details.isJailBreak === false ? '✅ 正常' : '❓ 未知')
              .fontSize(14)
              .fontColor(result.details.isJailBreak === true ? '#FF9800' :
                        result.details.isJailBreak === false ? '#4CAF50' : '#999999')
          }
          .width('100%')
          .margin({ bottom: 8 })

          // 模拟器检测
          Row() {
            Text('模拟器检测:')
              .fontSize(14)
              .fontColor('#666666')
            Blank()
            Text(result.details.isEmulator === true ? '⚠️ 模拟器环境' :
                  result.details.isEmulator === false ? '✅ 真实设备' : '❓ 未知')
              .fontSize(14)
              .fontColor(result.details.isEmulator === true ? '#FF9800' :
                        result.details.isEmulator === false ? '#4CAF50' : '#999999')
          }
          .width('100%')
          .margin({ bottom: 8 })

          // 攻击检测
          Row() {
            Text('攻击检测:')
              .fontSize(14)
              .fontColor('#666666')
            Blank()
            Text(result.details.isAttack === true ? '⚠️ 检测到攻击' :
                  result.details.isAttack === false ? '✅ 无攻击' : '❓ 未知')
              .fontSize(14)
              .fontColor(result.details.isAttack === true ? '#FF9800' :
                        result.details.isAttack === false ? '#4CAF50' : '#999999')
          }
          .width('100%')
          .margin({ bottom: 8 })

          // 风险等级
          if (result.details.riskLevel) {
            Row() {
              Text('风险等级:')
                .fontSize(14)
                .fontColor('#666666')
              Blank()
              Text(result.details.riskLevel === 'low' ? '低风险' : '高风险')
                .fontSize(14)
                .fontWeight(FontWeight.Medium)
                .fontColor(result.details.riskLevel === 'low' ? '#4CAF50' : '#FF9800')
            }
            .width('100%')
          }
        }
        .width('100%')
        .padding(12)
        .backgroundColor('#F5F5F5')
        .borderRadius(8)
        .margin({ bottom: 12 })
      }

      // 解析后的Payload信息
      if (result.jwsResult) {
        Text('解析后的Payload信息:')
          .fontSize(12)
          .fontColor('#666666')
          .width('100%')
          .margin({ bottom: 8 })

        Scroll() {
          Text(this.formatJson(JSON.stringify(result.jwsResult.payload, null, 2)))
            .fontSize(10)
            .fontColor('#333333')
            .fontFamily('monospace')
            .width('100%')
        }
        .width('100%')
        .height(150)
        .scrollBar(BarState.Auto)
        .backgroundColor('#F8F8F8')
        .borderRadius(8)
        .padding(12)
        .margin({ bottom: 12 })
      }

      // 原始JWS结果
      if (result.resultJson) {
        Text('原始JWS结果:')
          .fontSize(12)
          .fontColor('#666666')
          .width('100%')
          .margin({ bottom: 8 })

        Scroll() {
          Text(this.formatJson(result.resultJson))
            .fontSize(10)
            .fontColor('#333333')
            .fontFamily('monospace')
            .width('100%')
        }
        .width('100%')
        .height(120)
        .scrollBar(BarState.Auto)
        .backgroundColor('#F8F8F8')
        .borderRadius(8)
        .padding(12)
        .margin({ bottom: 12 })
      }

      // 错误信息
      if (result.error) {
        Text(`错误: ${result.error}`)
          .fontSize(12)
          .fontColor('#F44336')
          .width('100%')
          .margin({ top: 8 })
      }
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
    .margin({ top: 12, left: 16, right: 16 })
  }
}
```

---

## 3. EntryAbility.ets

**文件路径**: `entry/src/main/ets/entryability/EntryAbility.ets`

**功能**: 应用入口类，管理应用生命周期

```typescript
import { AbilityConstant, UIAbility, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { window } from '@kit.ArkUI';

const DOMAIN: number = 0x0000;

export default class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(DOMAIN, 'EntryAbility', 'Ability onCreate');
  }

  onDestroy(): void {
    hilog.info(DOMAIN, 'EntryAbility', 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    hilog.info(DOMAIN, 'EntryAbility', 'Ability onWindowStageCreate');

    windowStage.loadContent('pages/Index', (err) => {
      if (err.code) {
        hilog.error(DOMAIN, 'EntryAbility', 'Failed to load the content. Cause: %{public}s', JSON.stringify(err) ?? '');
        return;
      }
      hilog.info(DOMAIN, 'EntryAbility', 'Succeeded in loading the content.');
    });
  }

  onWindowStageDestroy(): void {
    hilog.info(DOMAIN, 'EntryAbility', 'Ability onWindowStageDestroy');
  }

  onForeground(): void {
    hilog.info(DOMAIN, 'EntryAbility', 'Ability onForeground');
  }

  onBackground(): void {
    hilog.info(DOMAIN, 'EntryAbility', 'Ability onBackground');
  }
}
```

---

## 4. 缺失的组件说明

### LocationUtil.ets

**状态**: 缺失，需要实现

**需要实现的功能**:
1. `init(context: Context): void` - 初始化位置服务
2. `checkLocationPermissions(): Promise<boolean>` - 检查位置权限
3. `requestLocationPermissions(): Promise<boolean>` - 请求位置权限
4. `getCurrentLocation(request: LocationRequest): Promise<LocationData>` - 获取当前位置
5. `LocationData` 接口定义

**参考API**: `@kit.LocationKit` 的 `geoLocationManager`

---

## 关键技术点说明

### 1. ArkTS语法限制
- ❌ 不支持字符串索引访问: `str[i]`
- ✅ 必须使用: `str.charAt(i)`
- ❌ 不支持 `any` 类型
- ❌ 不支持对象字面量类型声明
- ✅ 静态方法必须用类名调用，不能用 `this`

### 2. 华为Device Security Kit集成
- **正确导入**: `import { safetyDetect } from '@kit.DeviceSecurityKit';`
- **API调用**: `await safetyDetect.checkSysIntegrity(request);`
- **JWS响应格式**: `header.payload.signature`
- **Nonce要求**: 16-66字节的Base64编码随机字符串

### 3. Base64解码实现
由于ArkTS不支持浏览器的 `atob()` API，需要手动实现Base64解码，特别要注意：
- Base64URL格式转换 (`-` → `+`, `_` → `/`)
- Padding补齐
- 位运算解码

### 4. 项目配置文件
创建新项目时需要的配置：
- `build-profile.json5` - 构建配置
- `hvigor/hvigor-config.json5` - Hvigor版本配置
- `oh-package.json5` - 包管理配置
- `AppScope/app.json5` - 应用级配置
- `entry/src/main/module.json5` - 模块配置

### 5. 权限配置
在 `module.json5` 中需要的权限：
- `ohos.permission.LOCATION` - 精确位置
- `ohos.permission.APPROXIMATELY_LOCATION` - 大概位置
- `ohos.permission.INTERNET` - 网络访问

---

## 重新创建项目建议

1. 使用DevEco Studio创建新的Empty Ability项目
2. SDK版本选择: 6.0.2 (API 22)
3. 项目模型: Stage
4. 将上述三个核心文件复制到对应位置
5. 实现LocationUtil.ets或移除相关功能
6. 配置module.json5添加所需权限
7. 确保build-profile.json5配置正确

---

## API参考

- **Device Security Kit**: https://developer.huawei.com/consumer/cn/doc/harmonyos-guides-V14/devicesecurity-sysintegrity-check-V14
- **Location Kit**: https://developer.huawei.com/consumer/cn/doc/harmonyos-guides-V14/location-geolocation-V14
- **ArkTS语法规范**: 参考HarmonyOS官方文档
