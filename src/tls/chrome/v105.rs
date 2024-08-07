use super::CIPHER_LIST;
use crate::tls::extension::{ChromeExtension, Extension, SslExtension};
use crate::tls::profile::{Http2Settings, ImpersonateSettings};
use crate::tls::BoringTlsConnector;
use http::{
    header::{
        ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, DNT, UPGRADE_INSECURE_REQUESTS, USER_AGENT,
    },
    HeaderMap, HeaderValue,
};

pub(crate) fn get_settings(headers: HeaderMap) -> ImpersonateSettings {
    ImpersonateSettings {
        tls_connector: BoringTlsConnector::new(|| {
            ChromeExtension::builder()?.configure_cipher_list(&CIPHER_LIST)
        }),
        http2: Http2Settings {
            initial_stream_window_size: Some(6291456),
            initial_connection_window_size: Some(15728640),
            max_concurrent_streams: Some(1000),
            max_header_list_size: Some(262144),
            header_table_size: Some(65536),
            enable_push: None,
        },
        headers: create_headers(headers),
        gzip: true,
        brotli: true,
        zstd: false,
    }
}

fn create_headers(mut headers: HeaderMap) -> HeaderMap {
    headers.insert(
        "sec-ch-ua",
        "\"Google Chrome\";v=\"105\", \"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"105\""
            .parse()
            .unwrap(),
    );
    headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    headers.insert(
        "sec-ch-ua-platform",
        HeaderValue::from_static("\"Windows\""),
    );
    headers.insert(DNT, HeaderValue::from_static("1"));
    headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"));
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

    headers
}
