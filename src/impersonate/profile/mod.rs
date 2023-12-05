//! Settings for impersonating the Chrome impersonate

use crate::ClientBuilder;

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
#[derive(Debug)]
#[allow(missing_docs)]
pub enum Impersonate {
    Chrome104,
    Chrome105,
    Chrome106,
    Chrome108,
    Chrome107,
    Chrome109,
    Chrome114,
    Chrome118,
    Chrome119,
    Chrome99Android,
    Safari12,
    OkHttp3_9,
    OkHttp3_11,
    OkHttp3_13,
    OkHttp3_14,
    OkHttp4_9,
    OkHttp4_10,
    OkHttp5,
}

impl Impersonate {
    /// Get the client profile for the given impersonate version
    pub fn profile(&self) -> ClientProfile {
        match self {
            Impersonate::Chrome104
            | Impersonate::Chrome105
            | Impersonate::Chrome106
            | Impersonate::Chrome108
            | Impersonate::Chrome107
            | Impersonate::Chrome109
            | Impersonate::Chrome114
            | Impersonate::Chrome118
            | Impersonate::Chrome119
            | Impersonate::Chrome99Android => ClientProfile::Chrome,
            Impersonate::OkHttp3_9
            | Impersonate::OkHttp3_11
            | Impersonate::OkHttp3_13
            | Impersonate::OkHttp3_14
            | Impersonate::OkHttp4_9
            | Impersonate::OkHttp4_10
            | Impersonate::OkHttp5
            | Impersonate::Safari12 => ClientProfile::OkHttp,
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
}

impl ToString for ClientProfile {
    fn to_string(&self) -> String {
        match self {
            ClientProfile::Chrome => "chrome".to_string(),
            ClientProfile::OkHttp => "okhttp".to_string(),
        }
    }
}
