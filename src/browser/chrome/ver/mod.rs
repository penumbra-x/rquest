use crate::browser::BrowserSettings;

use super::ChromeVersion;

mod v104;
mod v105;
mod v106;
mod v108;
mod v110;
mod v99_android;

pub(super) fn get_config_from_ver(ver: ChromeVersion) -> BrowserSettings {
    match ver {
        ChromeVersion::V104 => v104::get_settings(),
        ChromeVersion::V105 => v105::get_settings(),
        ChromeVersion::V106 => v106::get_settings(),
        ChromeVersion::V108 => v108::get_settings(),
        ChromeVersion::V110 => v110::get_settings(),
        ChromeVersion::V99Android => v99_android::get_settings(),
    }
}
