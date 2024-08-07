#![allow(missing_docs)]

use boring::error::ErrorStack;
use boring::ssl::{
    CertCompressionAlgorithm, ConnectConfiguration, SslConnector, SslConnectorBuilder, SslCurve,
    SslMethod, SslOptions, SslVersion,
};
use foreign_types::ForeignTypeRef;

/// Extension trait for `SslConnector`.
pub trait Extension {
    /// The signature algorithms list.
    type SigalgsList;

    /// Create a new `SslConnectorBuilder`.
    fn builder() -> Result<SslConnectorBuilder, ErrorStack>;
}

/// Extension trait for `SslConnectorBuilder`.
pub trait SslExtension {
    /// Configure chrome to use the curves. (Chrome 123+)
    fn configure_chrome_new_curves(self) -> Result<SslConnectorBuilder, ErrorStack>;

    /// Configure the certificate verification for the given `SslConnectorBuilder`.
    fn configure_cert_verification(
        self,
        certs_verification: bool,
    ) -> Result<SslConnectorBuilder, ErrorStack>;

    /// Configure the ALPN and certificate settings for the given `SslConnectorBuilder`.
    fn configure_alpn_protos(self, h2: bool) -> Result<SslConnectorBuilder, ErrorStack>;

    /// Configure the cipher list for the given `SslConnectorBuilder`.
    fn configure_cipher_list(self, cipher: &[&str]) -> Result<SslConnectorBuilder, ErrorStack>;
}

/// Context Extension trait for `ConnectConfiguration`.
pub trait SslConnectExtension {
    /// Configure the permute_extensions for the given `ConnectConfiguration`.
    fn configure_permute_extensions(
        &mut self,
        permute_extensions: bool,
    ) -> &mut ConnectConfiguration;

    /// Configure the enable_ech_grease for the given `ConnectConfiguration`.
    fn configure_enable_ech_grease(&mut self, enable_ech_grease: bool)
        -> &mut ConnectConfiguration;

    /// Configure the add_application_settings for the given `ConnectConfiguration`.
    fn configure_add_application_settings(&mut self, h2: bool) -> &mut ConnectConfiguration;
}

#[derive(Debug)]
pub struct ChromeExtension;

impl Extension for ChromeExtension {
    type SigalgsList = [&'static str; 8];

    fn builder() -> Result<SslConnectorBuilder, ErrorStack> {
        const SIGALGS_LIST: <ChromeExtension as Extension>::SigalgsList = [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
        ];

        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.set_default_verify_paths()?;
        builder.set_grease_enabled(true);
        builder.enable_ocsp_stapling();
        builder.set_curves(&[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1])?;
        builder.set_sigalgs_list(&SIGALGS_LIST.join(":"))?;
        builder.enable_signed_cert_timestamps();
        builder.add_cert_compression_alg(CertCompressionAlgorithm::Brotli)?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        Ok(builder)
    }
}

#[derive(Debug)]
pub struct EdgeExtension;

impl Extension for EdgeExtension {
    type SigalgsList = [&'static str; 8];

    fn builder() -> Result<SslConnectorBuilder, ErrorStack> {
        const SIGALGS_LIST: <EdgeExtension as Extension>::SigalgsList = [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
        ];

        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.set_default_verify_paths()?;
        builder.set_grease_enabled(true);
        builder.enable_ocsp_stapling();
        builder.set_curves(&[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1])?;
        builder.set_sigalgs_list(&SIGALGS_LIST.join(":"))?;
        builder.enable_signed_cert_timestamps();
        builder.add_cert_compression_alg(CertCompressionAlgorithm::Brotli)?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        Ok(builder)
    }
}

#[derive(Debug)]
pub struct SafariExtension;

impl Extension for SafariExtension {
    type SigalgsList = [&'static str; 11];

    fn builder() -> Result<SslConnectorBuilder, ErrorStack> {
        const SIGALGS_LIST: <SafariExtension as Extension>::SigalgsList = [
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
}

#[derive(Debug)]
pub struct OkHttpExtension;

impl Extension for OkHttpExtension {
    type SigalgsList = [&'static str; 9];

    fn builder() -> Result<SslConnectorBuilder, ErrorStack> {
        const SIGALGS_LIST: <OkHttpExtension as Extension>::SigalgsList = [
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

        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.set_default_verify_paths()?;
        builder.enable_ocsp_stapling();
        builder.set_curves(&[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1])?;
        builder.set_sigalgs_list(&SIGALGS_LIST.join(":"))?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        Ok(builder)
    }
}

impl SslExtension for SslConnectorBuilder {
    fn configure_chrome_new_curves(mut self) -> Result<SslConnectorBuilder, ErrorStack> {
        self.set_curves(&[
            SslCurve::X25519_KYBER768_DRAFT00,
            SslCurve::X25519,
            SslCurve::SECP256R1,
            SslCurve::SECP384R1,
        ])?;
        Ok(self)
    }

    fn configure_cert_verification(
        mut self,
        certs_verification: bool,
    ) -> Result<SslConnectorBuilder, ErrorStack> {
        if !certs_verification {
            self.set_verify(boring::ssl::SslVerifyMode::NONE);
        }
        Ok(self)
    }

    fn configure_alpn_protos(mut self, h2: bool) -> Result<SslConnectorBuilder, ErrorStack> {
        if h2 {
            self.set_alpn_protos(b"\x02h2\x08http/1.1")?;
        } else {
            self.set_alpn_protos(b"\x08http/1.1")?;
        }
        Ok(self)
    }

    fn configure_cipher_list(mut self, cipher: &[&str]) -> Result<SslConnectorBuilder, ErrorStack> {
        self.set_cipher_list(&cipher.join(":"))?;
        Ok(self)
    }
}

impl SslConnectExtension for ConnectConfiguration {
    fn configure_permute_extensions(
        &mut self,
        permute_extensions: bool,
    ) -> &mut ConnectConfiguration {
        if permute_extensions {
            unsafe {
                boring_sys::SSL_set_permute_extensions(self.as_ptr(), 1);
            }
        }
        self
    }

    fn configure_enable_ech_grease(
        &mut self,
        enable_ech_grease: bool,
    ) -> &mut ConnectConfiguration {
        if enable_ech_grease {
            unsafe { boring_sys::SSL_set_enable_ech_grease(self.as_ptr(), 1) }
        }
        self
    }

    fn configure_add_application_settings(&mut self, h2: bool) -> &mut ConnectConfiguration {
        if h2 {
            const ALPN_H2: &str = "h2";
            const ALPN_H2_LENGTH: usize = 2;
            unsafe {
                boring_sys::SSL_add_application_settings(
                    self.as_ptr(),
                    ALPN_H2.as_ptr(),
                    ALPN_H2_LENGTH,
                    std::ptr::null(),
                    0,
                );
            };
        }
        self
    }
}
