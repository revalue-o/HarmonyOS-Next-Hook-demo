export const nativeIsLocationEnabled: () => boolean;
export const nativeGetCurrentLocation: () => Promise<NativeLocationData>;

export interface NativeLocationData {
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
