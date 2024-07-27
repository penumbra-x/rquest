use boring::{
    error::ErrorStack,
    ssl::{CertCompressionAlgorithm, SslConnector, SslConnectorBuilder, SslMethod, SslVersion},
};
pub mod v100;
pub mod v101;
pub mod v104;
pub mod v105;
pub mod v106;
pub mod v107;
pub mod v108;
pub mod v109;
pub mod v114;
pub mod v116;
pub mod v117;
pub mod v118;
pub mod v119;
pub mod v120;
pub mod v123;
pub mod v124;
pub mod v126;

const SIGALGS_LIST: [&str; 8] = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
];

const CIPHER_LIST: [&str; 15] = [
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
];

fn ssl_builder() -> Result<SslConnectorBuilder, ErrorStack> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    builder.set_default_verify_paths()?;

    builder.set_grease_enabled(true);

    builder.enable_ocsp_stapling();

    builder.set_cipher_list(&CIPHER_LIST.join(":"))?;

    builder.set_sigalgs_list(&SIGALGS_LIST.join(":"))?;

    builder.enable_signed_cert_timestamps();

    builder.add_cert_compression_alg(CertCompressionAlgorithm::Brotli)?;

    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;

    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    Ok(builder)
}
