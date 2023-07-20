use boring::ssl::{
    CertCompressionAlgorithm, SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode,
    SslVersion,
};
use http::{
    header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, UPGRADE_INSECURE_REQUESTS, USER_AGENT},
    HeaderMap, HeaderValue,
};
use std::sync::Arc;

use crate::browser::{BrowserSettings, Http2Data};

pub(super) fn get_settings() -> BrowserSettings {
    BrowserSettings {
        tls_builder_func: Arc::new(create_ssl_connector),
        http2: Http2Data {
            initial_stream_window_size: 6291456,
            initial_connection_window_size: 15663105,
            max_concurrent_streams: 1000,
            max_header_list_size: 262144,
            header_table_size: 65536,
            enable_push: Some(false),
        },
        headers: create_headers(),
        gzip: true,
        brotli: true,
    }
}

fn create_ssl_connector() -> SslConnectorBuilder {
    let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();

    builder.set_grease_enabled(true);

    builder.enable_ocsp_stapling();

    builder.set_verify(SslVerifyMode::NONE);

    let cipher_list = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA,AES256-SHA",
    ];

    builder.set_cipher_list(&cipher_list.join(":")).unwrap();

    let sigalgs_list = [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
    ];

    builder.set_sigalgs_list(&sigalgs_list.join(":")).unwrap();

    builder.enable_signed_cert_timestamps();

    builder.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();

    builder
        .add_cert_compression_alg(CertCompressionAlgorithm::Brotli)
        .unwrap();

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();

    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();

    builder
}

fn create_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();

    headers.insert(
        "sec-ch-ua",
        HeaderValue::from_static(
            r#""Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"#,
        ),
    );
    headers.insert("sec-ch-ua-mobile", "?0".parse().unwrap());
    headers.insert("sec-ch-ua-platform", "\"Windows\"".parse().unwrap());
    headers.insert(UPGRADE_INSECURE_REQUESTS, "1".parse().unwrap());
    headers.insert(USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36".parse().unwrap());
    headers.insert(ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".parse().unwrap());
    headers.insert("sec-fetch-site", "none".parse().unwrap());
    headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
    headers.insert("sec-fetch-user", "?1".parse().unwrap());
    headers.insert("sec-fetch-dest", "document".parse().unwrap());
    headers.insert(ACCEPT_ENCODING, "gzip, deflate, br".parse().unwrap());
    headers.insert(ACCEPT_LANGUAGE, "en-US,en;q=0.9".parse().unwrap());

    headers
}
