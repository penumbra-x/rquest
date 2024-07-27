use boring::{
    error::ErrorStack,
    ssl::{SslConnector, SslConnectorBuilder, SslCurve, SslMethod, SslVersion},
};

pub mod okhttp3_11;
pub mod okhttp3_13;
pub mod okhttp3_14;
pub mod okhttp3_9;
pub mod okhttp4_10;
pub mod okhttp4_9;
pub mod okhttp5;

const SIGALGS_LIST: [&str; 9] = [
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

fn base_ssl_builder() -> Result<SslConnectorBuilder, ErrorStack> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    builder.set_default_verify_paths()?;

    builder.enable_ocsp_stapling();

    builder.set_curves(&[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1])?;

    builder.set_sigalgs_list(&SIGALGS_LIST.join(":"))?;

    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;

    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    Ok(builder)
}
