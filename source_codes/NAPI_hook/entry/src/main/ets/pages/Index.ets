import { hilog } from '@kit.PerformanceAnalysisKit';
import testNapi from 'libentry.so';
import { abilityAccessCtrl, Permissions } from '@kit.AbilityKit';

const DOMAIN = 0x0000;
const TAG = 'NAPI_HOOK';

@Entry
@Component
struct Index {
  @State message: string = 'Hello World';
  @State latitude: string = '--';
  @State longitude: string = '--';
  @State altitude: string = '--';
  @State accuracy: string = '--';
  @State speed: string = '--';
  @State isLoading: boolean = false;

  async requestPermissions(): Promise<boolean> {
    const permissions: Permissions[] = [
      'ohos.permission.APPROXIMATELY_LOCATION',
      'ohos.permission.LOCATION'
    ];
    const atManager = abilityAccessCtrl.createAtManager();
    try {
      const result = await atManager.requestPermissionsFromUser(getContext(this), permissions);
      for (let i = 0; i < result.authResults.length; i++) {
        if (result.authResults[i] !== 0) {
          hilog.error(DOMAIN, TAG, 'Permission denied: %{public}s', permissions[i]);
          return false;
        }
      }
      hilog.info(DOMAIN, TAG, 'All permissions granted');
      return true;
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'Request permission failed: %{public}s', JSON.stringify(err));
      return false;
    }
  }

  build() {
    Row() {
      Column({ space: 15 }) {
        Text(this.message)
          .fontSize($r('app.float.page_text_font_size'))
          .fontWeight(FontWeight.Bold)

        Text(`Latitude: ${this.latitude}`)
          .fontSize(20)
          .margin({ top: 20 })
        Text(`Longitude: ${this.longitude}`)
          .fontSize(20)
        Text(`Altitude: ${this.altitude}`)
          .fontSize(18)
          .fontColor('#666666')
        Text(`Accuracy: ${this.accuracy}`)
          .fontSize(18)
          .fontColor('#666666')
        Text(`Speed: ${this.speed}`)
          .fontSize(18)
          .fontColor('#666666')

        Button(this.isLoading ? 'Locating...' : 'Get Location')
          .width(200)
          .height(50)
          .fontSize(18)
          .backgroundColor(this.isLoading ? '#999999' : '#007DFF')
          .enabled(!this.isLoading)
          .onClick(async () => {
            // Request permissions
            const granted = await this.requestPermissions();
            if (!granted) {
              this.message = 'Permission denied';
              return;
            }

            // Check location switch
            const enabled = testNapi.nativeIsLocationEnabled();
            if (!enabled) {
              this.message = 'Please enable location';
              return;
            }

            // Start locating
            this.isLoading = true;
            this.message = 'Locating...';

            try {
              const loc = await testNapi.nativeGetCurrentLocation() as Record<string, number>;
              this.latitude = loc.latitude.toFixed(6);
              this.longitude = loc.longitude.toFixed(6);
              this.altitude = loc.altitude.toFixed(2);
              this.accuracy = loc.accuracy.toFixed(2);
              this.speed = loc.speed.toFixed(2);
              this.message = 'Location obtained';
              hilog.info(DOMAIN, TAG, 'Location: lat=%{public}s, lon=%{public}s', this.latitude, this.longitude);
            } catch (err) {
              this.message = 'Failed: ' + JSON.stringify(err);
              hilog.error(DOMAIN, TAG, 'Get location failed: %{public}s', JSON.stringify(err));
            } finally {
              this.isLoading = false;
            }
          })
      }
      .width('100%')
    }
    .height('100%')
  }
}
