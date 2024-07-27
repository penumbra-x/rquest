pub mod safari15_3;
pub mod safari15_5;
pub mod safari15_6_1;
pub mod safari16;
pub mod safari16_5;
pub mod safari17_2_1;
pub mod safari17_4_1;
pub mod safari17_5;
pub mod safari_ios_16_5;
pub mod safari_ios_17_2;
pub mod safari_ios_17_4_1;

use boring::{
    error::ErrorStack,
    ssl::{
        CertCompressionAlgorithm, SslConnector, SslConnectorBuilder, SslCurve, SslMethod,
        SslOptions, SslVersion,
    },
};

const SIGALGS_LIST: [&str; 11] = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_sha1",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
    "rsa_pkcs1_sha1",
];

fn base_ssl_builder() -> Result<SslConnectorBuilder, ErrorStack> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    builder.set_default_verify_paths()?;

    builder.set_options(SslOptions::NO_TICKET);

    builder.set_grease_enabled(true);

    builder.enable_ocsp_stapling();

    builder.set_sigalgs_list(&SIGALGS_LIST.join(":"))?;

    builder.set_curves(&[
        SslCurve::X25519,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
        SslCurve::SECP521R1,
    ])?;

    builder.enable_signed_cert_timestamps();

    builder.add_cert_compression_alg(CertCompressionAlgorithm::Zlib)?;

    builder.set_min_proto_version(Some(SslVersion::TLS1))?;

    Ok(builder)
}
