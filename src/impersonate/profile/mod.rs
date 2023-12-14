//! Settings for impersonating the Chrome impersonate

use crate::ClientBuilder;
use std::str::FromStr;
mod ver;

pub(crate) fn configure_impersonate(ver: Impersonate, builder: ClientBuilder) -> ClientBuilder {
    let settings = ver::get_config_from_ver(ver);
    builder
        .use_boring_tls(settings.tls_builder_func)
        .http2_initial_stream_window_size(settings.http2.initial_stream_window_size)
        .http2_initial_connection_window_size(settings.http2.initial_connection_window_size)
        .http2_max_concurrent_streams(settings.http2.max_concurrent_streams)
        .http2_max_header_list_size(settings.http2.max_header_list_size)
        .http2_header_table_size(settings.http2.header_table_size)
        .http2_enable_push(settings.http2.enable_push)
        .replace_default_headers(settings.headers)
        .brotli(settings.brotli)
        .gzip(settings.gzip)
}

/// Defines the Chrome version to mimic when setting up a builder
#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub enum Impersonate {
    Chrome99,
    Chrome104,
    Chrome105,
    Chrome106,
    Chrome108,
    Chrome107,
    Chrome109,
    Chrome114,
    Chrome116,
    Chrome118,
    Chrome119,
    Safari12,
    Safari15_3,
    Safari15_5,
    Safari15_6_1,
    Safari16,
    OkHttp3_9,
    OkHttp3_11,
    OkHttp3_13,
    OkHttp3_14,
    OkHttp4_9,
    OkHttp4_10,
    OkHttp5,
}

/// Impersonate version from string
impl FromStr for Impersonate {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chrome99" => Ok(Impersonate::Chrome99),
            "chrome104" => Ok(Impersonate::Chrome104),
            "chrome105" => Ok(Impersonate::Chrome105),
            "chrome106" => Ok(Impersonate::Chrome106),
            "chrome108" => Ok(Impersonate::Chrome108),
            "chrome107" => Ok(Impersonate::Chrome107),
            "chrome109" => Ok(Impersonate::Chrome109),
            "chrome114" => Ok(Impersonate::Chrome114),
            "chrome116" => Ok(Impersonate::Chrome116),
            "chrome118" => Ok(Impersonate::Chrome118),
            "chrome119" => Ok(Impersonate::Chrome119),
            "safari12" => Ok(Impersonate::Safari12),
            "safari15_3" => Ok(Impersonate::Safari15_3),
            "safari15_5" => Ok(Impersonate::Safari15_5),
            "safari15_6_1" => Ok(Impersonate::Safari15_6_1),
            "safari16" => Ok(Impersonate::Safari16),
            "okhttp3_9" => Ok(Impersonate::OkHttp3_9),
            "okhttp3_11" => Ok(Impersonate::OkHttp3_11),
            "okhttp3_13" => Ok(Impersonate::OkHttp3_13),
            "okhttp3_14" => Ok(Impersonate::OkHttp3_14),
            "okhttp4_9" => Ok(Impersonate::OkHttp4_9),
            "okhttp4_10" => Ok(Impersonate::OkHttp4_10),
            "okhttp5" => Ok(Impersonate::OkHttp5),
            _ => Err("Invalid Impersonate version"),
        }
    }
}

impl Impersonate {
    /// Get the client profile for the given impersonate version
    pub fn profile(&self) -> ClientProfile {
        match self {
            Impersonate::Chrome99
            | Impersonate::Chrome104
            | Impersonate::Chrome105
            | Impersonate::Chrome106
            | Impersonate::Chrome108
            | Impersonate::Chrome107
            | Impersonate::Chrome109
            | Impersonate::Chrome114
            | Impersonate::Chrome116
            | Impersonate::Chrome118
            | Impersonate::Chrome119 => ClientProfile::Chrome,

            Impersonate::Safari12
            | Impersonate::Safari15_3
            | Impersonate::Safari15_5
            | Impersonate::Safari15_6_1
            | Impersonate::Safari16 => ClientProfile::Safari,

            Impersonate::OkHttp3_9
            | Impersonate::OkHttp3_11
            | Impersonate::OkHttp3_13
            | Impersonate::OkHttp3_14
            | Impersonate::OkHttp4_9
            | Impersonate::OkHttp4_10
            | Impersonate::OkHttp5 => ClientProfile::OkHttp,
        }
    }
}

/// impersonate client profile
#[derive(Clone, Copy, Debug)]
pub enum ClientProfile {
    /// Chrome impersonate client profile
    Chrome,
    /// OkHttp impersonate client profile
    OkHttp,
    /// Safari impersonate client profile
    Safari,
}

impl ToString for ClientProfile {
    fn to_string(&self) -> String {
        match self {
            ClientProfile::Chrome => "chrome".to_string(),
            ClientProfile::OkHttp => "okhttp".to_string(),
            ClientProfile::Safari => "safari".to_string(),
        }
    }
}
