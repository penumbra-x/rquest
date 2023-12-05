use crate::impersonate::ImpersonateSettings;

use super::Impersonate;

mod okhttp3_11;
mod okhttp3_13;
mod okhttp3_14;
mod okhttp3_9;
mod okhttp4_10;
mod okhttp4_9;
mod okhttp5;
mod safari12;
mod v104;
mod v105;
mod v106;
mod v107;
mod v108;
mod v109;
mod v114;
mod v118;
mod v119;
mod v99_android;

pub(super) fn get_config_from_ver(ver: Impersonate) -> ImpersonateSettings {
    match ver {
        Impersonate::Chrome104 => v104::get_settings(ver.profile()),
        Impersonate::Chrome105 => v105::get_settings(ver.profile()),
        Impersonate::Chrome106 => v106::get_settings(ver.profile()),
        Impersonate::Chrome107 => v107::get_settings(ver.profile()),
        Impersonate::Chrome108 => v108::get_settings(ver.profile()),
        Impersonate::Chrome109 => v109::get_settings(ver.profile()),
        Impersonate::Chrome114 => v114::get_settings(ver.profile()),
        Impersonate::Chrome118 => v118::get_settings(ver.profile()),
        Impersonate::Chrome119 => v119::get_settings(ver.profile()),
        Impersonate::Chrome99Android => v99_android::get_settings(ver.profile()),
        Impersonate::Safari12 => safari12::get_settings(ver.profile()),
        Impersonate::OkHttp3_9 => okhttp3_9::get_settings(ver.profile()),
        Impersonate::OkHttp3_11 => okhttp3_11::get_settings(ver.profile()),
        Impersonate::OkHttp3_13 => okhttp3_13::get_settings(ver.profile()),
        Impersonate::OkHttp3_14 => okhttp3_14::get_settings(ver.profile()),
        Impersonate::OkHttp4_9 => okhttp4_9::get_settings(ver.profile()),
        Impersonate::OkHttp4_10 => okhttp4_10::get_settings(ver.profile()),
        Impersonate::OkHttp5 => okhttp5::get_settings(ver.profile()),
    }
}
