#![allow(missing_docs)]

use super::Version;
use crate::async_impl::client::HttpVersionPref;
use boring::error::ErrorStack;
use boring::ssl::{
    CertCompressionAlgorithm, ConnectConfiguration, SslConnector, SslConnectorBuilder, SslCurve,
    SslMethod, SslOptions, SslVerifyMode, SslVersion,
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
    fn configure_alpn_protos(
        self,
        http_version: &HttpVersionPref,
    ) -> Result<SslConnectorBuilder, ErrorStack>;

    /// Configure the cipher list for the given `SslConnectorBuilder`.
    fn configure_cipher_list(self, cipher: &[&str]) -> Result<SslConnectorBuilder, ErrorStack>;

    /// Configure the minimum TLS version for the given `SslConnectorBuilder`.
    fn configure_min_tls_version(
        self,
        min_tls_version: Option<Version>,
    ) -> Result<SslConnectorBuilder, ErrorStack>;

    /// Configure the maximum TLS version for the given `SslConnectorBuilder`.
    fn configure_max_tls_version(
        self,
        max_tls_version: Option<Version>,
    ) -> Result<SslConnectorBuilder, ErrorStack>;
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
    fn configure_add_application_settings(
        &mut self,
        http_version: HttpVersionPref,
    ) -> &mut ConnectConfiguration;
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
            self.set_verify(SslVerifyMode::NONE);
        } else {
            self.set_verify(SslVerifyMode::PEER);
        }
        Ok(self)
    }

    fn configure_alpn_protos(
        mut self,
        http_version: &HttpVersionPref,
    ) -> Result<SslConnectorBuilder, ErrorStack> {
        match http_version {
            HttpVersionPref::Http1 => {
                self.set_alpn_protos(b"\x08http/1.1")?;
            }
            HttpVersionPref::Http2 | HttpVersionPref::All => {
                self.set_alpn_protos(b"\x02h2\x08http/1.1")?;
            }
        }

        Ok(self)
    }

    fn configure_cipher_list(mut self, cipher: &[&str]) -> Result<SslConnectorBuilder, ErrorStack> {
        self.set_cipher_list(&cipher.join(":"))?;
        Ok(self)
    }

    fn configure_min_tls_version(
        mut self,
        min_tls_version: Option<Version>,
    ) -> Result<SslConnectorBuilder, ErrorStack> {
        if let Some(version) = min_tls_version {
            let ssl_version = match version.0 {
                super::InnerVersion::Tls1_0 => SslVersion::TLS1,
                super::InnerVersion::Tls1_1 => SslVersion::TLS1_1,
                super::InnerVersion::Tls1_2 => SslVersion::TLS1_2,
                super::InnerVersion::Tls1_3 => SslVersion::TLS1_3,
            };
            self.set_min_proto_version(Some(ssl_version))?
        }

        Ok(self)
    }

    fn configure_max_tls_version(
        mut self,
        max_tls_version: Option<Version>,
    ) -> Result<SslConnectorBuilder, ErrorStack> {
        if let Some(version) = max_tls_version {
            let ssl_version = match version.0 {
                super::InnerVersion::Tls1_0 => SslVersion::TLS1,
                super::InnerVersion::Tls1_1 => SslVersion::TLS1_1,
                super::InnerVersion::Tls1_2 => SslVersion::TLS1_2,
                super::InnerVersion::Tls1_3 => SslVersion::TLS1_3,
            };

            self.set_max_proto_version(Some(ssl_version))?
        }

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

    fn configure_add_application_settings(
        &mut self,
        http_version: HttpVersionPref,
    ) -> &mut ConnectConfiguration {
        let (alpn, alpn_len) = match http_version {
            HttpVersionPref::Http1 => ("http/1.1", 8),
            HttpVersionPref::Http2 | HttpVersionPref::All => ("h2", 2),
        };

        unsafe {
            boring_sys::SSL_add_application_settings(
                self.as_ptr(),
                alpn.as_ptr(),
                alpn_len,
                std::ptr::null(),
                0,
            );
        }

        self
    }
}
