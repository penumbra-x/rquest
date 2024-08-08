use crate::tls::extension::{Extension, OkHttpExtension, SslExtension};
use crate::tls::profile::{ConnectSettings, Http2Settings};
use http::{
    header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT},
    HeaderMap, HeaderValue,
};
use std::sync::Arc;

pub(crate) fn get_settings(headers: &mut HeaderMap) -> ConnectSettings {
    init_headers(headers);
    ConnectSettings {
        tls_builder: Arc::new(|| {
            OkHttpExtension::builder()?.configure_cipher_list(&[
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            ])
        }),
        http2: Http2Settings {
            initial_stream_window_size: Some(16777216),
            initial_connection_window_size: Some(16777216),
            max_concurrent_streams: None,
            max_header_list_size: None,
            header_table_size: None,
            enable_push: None,
        },
    }
}

fn init_headers(headers: &mut HeaderMap) {
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(
        ACCEPT_LANGUAGE,
        HeaderValue::from_static("de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"),
    );
    headers.insert(USER_AGENT, HeaderValue::from_static("GM-Android/6.112.2 (240590300; M:samsung SM-G781U1; O:33; D:edb34792871638d8) ObsoleteUrlFactory/1.0 OkHttp/4.10.0"));
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
}
