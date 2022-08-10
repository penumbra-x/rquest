use crate::browser::BrowserSettings;

use super::ChromeVersion;

mod v104;

pub(super) fn get_config_from_ver(ver: ChromeVersion) -> BrowserSettings {
    match ver {
        ChromeVersion::V104 => v104::get_settings(),
    }
}
