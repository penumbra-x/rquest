use super::ssl_builder;
use crate::impersonate::{BoringTlsConnector, Http2Data, ImpersonateSettings};
use http::{
    header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, UPGRADE_INSECURE_REQUESTS, USER_AGENT},
    HeaderMap, HeaderValue,
};

pub(crate) fn get_settings(headers: HeaderMap) -> ImpersonateSettings {
    ImpersonateSettings {
        tls_connector: BoringTlsConnector::new(ssl_builder),
        http2: Http2Data {
            initial_stream_window_size: Some(6291456),
            initial_connection_window_size: Some(15728640),
            max_concurrent_streams: None,
            max_header_list_size: Some(262144),
            header_table_size: Some(65536),
            enable_push: Some(false),
        },
        headers: create_headers(headers),
        gzip: true,
        brotli: true,
    }
}
fn create_headers(mut headers: HeaderMap) -> HeaderMap {
    headers.insert(
        "sec-ch-ua",
        HeaderValue::from_static(
            "\"Google Chrome\";v=\"123\", \"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"123\"",
        ),
    );
    headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
    headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"));
    headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
    headers.insert("Sec-Fetch-Site", HeaderValue::from_static("?1"));
    headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("same-site"));
    headers.insert("Sec-Fetch-User", HeaderValue::from_static("document"));
    headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("navigate"));
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br, zstd"),
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US;q=1.0"));

    headers
}
