use super::CIPHER_LIST;
use crate::tls::extension::{ChromeExtension, Extension, SslExtension};
use crate::tls::profile::{ConnectSettings, Http2Settings};
use http::{
    header::{
        ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, DNT, UPGRADE_INSECURE_REQUESTS, USER_AGENT,
    },
    HeaderMap, HeaderValue,
};
use std::sync::Arc;

pub(crate) fn get_settings(headers: &mut HeaderMap) -> ConnectSettings {
    init_headers(headers);
    ConnectSettings {
        tls_builder: Arc::new(|| ChromeExtension::builder()?.configure_cipher_list(&CIPHER_LIST)),
        http2: Http2Settings {
            initial_stream_window_size: Some(6291456),
            initial_connection_window_size: Some(15728640),
            max_concurrent_streams: Some(1000),
            max_header_list_size: Some(262144),
            header_table_size: Some(65536),
            enable_push: Some(false),
        },
    }
}

fn init_headers(headers: &mut HeaderMap) {
    headers.insert(
        "sec-ch-ua",
        HeaderValue::from_static(
            "\"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"108\", \"Google Chrome\";v=\"108\"",
        ),
    );
    headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    headers.insert(
        "sec-ch-ua-platform",
        HeaderValue::from_static("\"Windows\""),
    );
    headers.insert(DNT, HeaderValue::from_static("1"));
    headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"));
    headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
    headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
}
