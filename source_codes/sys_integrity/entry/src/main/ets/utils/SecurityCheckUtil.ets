import { BusinessError } from '@kit.BasicServicesKit';
import { Context } from '@kit.AbilityKit';
// import { safetyDetect } from '@kit.DeviceSecurityKit';  // API 13 不支持

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
