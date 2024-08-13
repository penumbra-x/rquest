use super::CIPHER_LIST;
use crate::tls::extension::{ChromeExtension, Extension, SslExtension};
use crate::tls::{Http2Settings, SslImpersonateSettings};
use crate::tls::{ImpersonateSettings, SslResult};
use http::{
    header::{
        ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, CACHE_CONTROL, DNT, UPGRADE_INSECURE_REQUESTS,
        USER_AGENT,
    },
    HeaderMap, HeaderValue,
};

pub(crate) fn get_settings(
    settings: ImpersonateSettings,
    headers: &mut HeaderMap,
) -> SslResult<SslImpersonateSettings> {
    init_headers(headers);
    Ok(SslImpersonateSettings {
        ssl_builder: ChromeExtension::builder()?.configure_cipher_list(&CIPHER_LIST)?,
        extension: settings.extension,
        http2: Http2Settings {
            initial_stream_window_size: Some(6291456),
            initial_connection_window_size: Some(15728640),
            max_concurrent_streams: None,
            max_header_list_size: Some(262144),
            header_table_size: Some(65536),
            enable_push: Some(false),
            headers_priority: settings.headers_priority,
            headers_pseudo_order: settings.headers_pseudo_order,
            settings_order: settings.settings_order,
        },
    })
}

fn init_headers(headers: &mut HeaderMap) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=0"));
    headers.insert(
        "sec-ch-ua",
        HeaderValue::from_static(
            r#""Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120""#,
        ),
    );
    headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    headers.insert(
        "sec-ch-ua-platform",
        HeaderValue::from_static("\"Windows\""),
    );
    headers.insert(DNT, HeaderValue::from_static("1"));
    headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"));
    headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
    headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
    headers.insert(
        ACCEPT_LANGUAGE,
        HeaderValue::from_static("en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
    );
}
