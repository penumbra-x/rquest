use boring::ssl::{SslConnector, SslConnectorBuilder, SslCurve, SslMethod, SslVersion};
use http::{
    header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT},
    HeaderMap,
};
use std::sync::Arc;

use crate::impersonate::profile::ClientProfile;
use crate::impersonate::{Http2Data, ImpersonateSettings};

pub(super) fn get_settings(profile: ClientProfile) -> ImpersonateSettings {
    ImpersonateSettings {
        tls_builder_func: Arc::new(create_ssl_connector),
        http2: Http2Data {
            initial_stream_window_size: Some(16777216),
            initial_connection_window_size: Some(16777216),
            max_concurrent_streams: None,
            max_header_list_size: None,
            header_table_size: None,
            enable_push: None,
        },
        headers: create_headers(profile),
        gzip: true,
        brotli: true,
    }
}

fn create_ssl_connector() -> SslConnectorBuilder {
    let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();

    builder.set_default_verify_paths().unwrap();

    builder.enable_ocsp_stapling();

    builder
        .set_curves(&[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1])
        .unwrap();

    let cipher_list = [
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
        "rsa_pkcs1_sha1",
    ];

    builder.set_sigalgs_list(&sigalgs_list.join(":")).unwrap();

    builder.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();

    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();

    builder
}

fn create_headers(profile: ClientProfile) -> HeaderMap {
    let mut headers = HeaderMap::new();

    headers.insert(ACCEPT, "*/*".parse().unwrap());
    headers.insert(
        ACCEPT_LANGUAGE,
        "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7".parse().unwrap(),
    );
    headers.insert(USER_AGENT, "okhttp/3.14".parse().unwrap());
    headers.insert(ACCEPT_ENCODING, "gzip, deflate, br".parse().unwrap());
    headers.insert("client_profile", profile.to_string().parse().unwrap());
    headers
}
