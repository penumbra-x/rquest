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
        .client_profile(settings.client_profile)
}

/// Defines the Chrome version to mimic when setting up a builder
#[derive(Debug)]
#[allow(missing_docs)]
pub enum Impersonate {
    Chrome104,
    Chrome105,
    Chrome106,
    Chrome108,
    Chrome109,
    Chrome114,
    Chrome99Android,
    OkHttpAndroid13,
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
