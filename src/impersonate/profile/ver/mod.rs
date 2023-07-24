use crate::impersonate::ImpersonateSettings;

use super::Impersonate;

mod okhttp_android13;
mod v104;
mod v105;
mod v106;
mod v108;
mod v109;
mod v114;
mod v99_android;

pub(super) fn get_config_from_ver(ver: Impersonate) -> ImpersonateSettings {
    match ver {
        Impersonate::Chrome104 => v104::get_settings(),
        Impersonate::Chrome105 => v105::get_settings(),
        Impersonate::Chrome106 => v106::get_settings(),
        Impersonate::Chrome108 => v108::get_settings(),
        Impersonate::Chrome109 => v109::get_settings(),
        Impersonate::Chrome114 => v114::get_settings(),
        Impersonate::Chrome99Android => v99_android::get_settings(),
        Impersonate::OkHttpAndroid13 => okhttp_android13::get_settings(),
    }
}
