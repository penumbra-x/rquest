use crate::impersonate::ImpersonateSettings;

use super::Impersonate;

mod okhttp3;
mod okhttp4;
mod v104;
mod v105;
mod v106;
mod v107;
mod v108;
mod v109;
mod v114;
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
        Impersonate::Chrome99Android => v99_android::get_settings(ver.profile()),
        Impersonate::OkHttp4 => okhttp4::get_settings(ver.profile()),
        Impersonate::OkHttp3 => okhttp3::get_settings(ver.profile()),
    }
}
