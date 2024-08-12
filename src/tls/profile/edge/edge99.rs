use super::CIPHER_LIST;
use crate::tls::extension::{EdgeExtension, Extension, SslExtension};
use crate::tls::{Http2Settings, SslBuilderSettings};
use crate::tls::{ImpersonateSettings, TlsResult};
use http::{
    header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, UPGRADE_INSECURE_REQUESTS, USER_AGENT},
    HeaderMap, HeaderValue,
};

pub(crate) fn get_settings(
    settings: ImpersonateSettings,
    headers: &mut HeaderMap,
) -> TlsResult<SslBuilderSettings> {
    init_headers(headers);
    Ok(SslBuilderSettings {
        ssl_builder: EdgeExtension::builder()?.configure_cipher_list(&CIPHER_LIST)?,
        enable_psk: settings.pre_share_key,
        http2: Http2Settings {
            initial_stream_window_size: Some(6291456),
            initial_connection_window_size: Some(15728640),
            max_concurrent_streams: Some(1000),
            max_header_list_size: Some(262144),
            header_table_size: Some(65536),
            enable_push: None,
            headers_priority: settings.headers_priority,
            headers_pseudo_order: settings.headers_pseudo_order,
            settings_order: settings.settings_order,
        },
    })
}

fn init_headers(headers: &mut HeaderMap) {
    headers.insert(
        "sec-ch-ua",
        HeaderValue::from_static(
            r#"" Not A;Brand";v="99", "Chromium";v="99", "Microsoft Edge";v="99""#,
        ),
    );
    headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    headers.insert(
        "sec-ch-ua-platform",
        HeaderValue::from_static("\"Windows\""),
    );
    headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.30"));
    headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
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
