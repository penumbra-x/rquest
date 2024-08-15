#![allow(missing_debug_implementations)]
use super::{cert_compression::CertCompressionAlgorithm, TlsResult, Version};
use crate::async_impl::client::HttpVersionPref;
use ::std::os::raw::c_int;
use boring::error::ErrorStack;
use boring::ssl::{
    ConnectConfiguration, SslConnector, SslConnectorBuilder, SslCurve, SslMethod, SslOptions,
    SslVerifyMode, SslVersion,
};
use foreign_types::ForeignTypeRef;
use std::path::Path;

/// Error handler for the boringssl functions.
fn sv_handler(r: c_int) -> Result<c_int, ErrorStack> {
    if r == 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

/// TlsBuilder trait for `SslConnectorBuilder`.
pub trait TlsBuilder {
    /// The signature algorithms list.
    type SigalgsList;

    /// Create a new `SslConnectorBuilder`.
    fn new(cipher: &[&str]) -> TlsResult<SslConnectorBuilder>;
}

/// TlsExtension trait for `SslConnectorBuilder`.
pub trait TlsExtension {
    /// Configure chrome to use the curves. (Chrome 123+)
    fn configure_chrome_new_curves(self) -> TlsResult<SslConnectorBuilder>;

    /// Configure the certificate verification for the given `SslConnectorBuilder`.
    fn configure_cert_verification(
        self,
        certs_verification: bool,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the ALPN and certificate settings for the given `SslConnectorBuilder`.
    fn configure_alpn_protos(self, http_version: HttpVersionPref)
        -> TlsResult<SslConnectorBuilder>;

    /// Configure the minimum TLS version for the given `SslConnectorBuilder`.
    fn configure_min_tls_version(
        self,
        min_tls_version: Option<Version>,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the maximum TLS version for the given `SslConnectorBuilder`.
    fn configure_max_tls_version(
        self,
        max_tls_version: Option<Version>,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the certificate compression algorithm for the given `SslConnectorBuilder`.
    fn configure_add_cert_compression_alg(
        self,
        cert_compression_alg: CertCompressionAlgorithm,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the ca certificate file for the given `SslConnectorBuilder`.
    fn configure_ca_cert_file<P: AsRef<Path>>(
        self,
        ca_cert_file: Option<P>,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the permute_extensions for the given `SslConnectorBuilder`.
    fn configure_permute_extensions(
        self,
        enable: bool,
        permute_extensions: bool,
    ) -> TlsResult<SslConnectorBuilder>;
}

/// TlsConnectExtension trait for `ConnectConfiguration`.
pub trait TlsConnectExtension {
    /// Configure the enable_ech_grease for the given `ConnectConfiguration`.
    fn configure_enable_ech_grease(
        &mut self,
        enable: bool,
        enable_ech_grease: bool,
    ) -> TlsResult<&mut ConnectConfiguration>;

    /// Configure the add_application_settings for the given `ConnectConfiguration`.
    fn configure_add_application_settings(
        &mut self,
        enable: bool,
        http_version: HttpVersionPref,
    ) -> TlsResult<&mut ConnectConfiguration>;
}

pub struct ChromeTlsBuilder;

impl TlsBuilder for ChromeTlsBuilder {
    type SigalgsList = [&'static str; 8];

    fn new(cipher: &[&str]) -> TlsResult<SslConnectorBuilder> {
        const SIGALGS_LIST: <ChromeTlsBuilder as TlsBuilder>::SigalgsList = [
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
        builder.set_cipher_list(&cipher.join(":"))?;
        builder.enable_signed_cert_timestamps();
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        builder.configure_add_cert_compression_alg(CertCompressionAlgorithm::Brotli)
    }
}

pub struct EdgeTlsBuilder;

impl TlsBuilder for EdgeTlsBuilder {
    type SigalgsList = [&'static str; 8];

    fn new(cipher: &[&str]) -> TlsResult<SslConnectorBuilder> {
        const SIGALGS_LIST: <EdgeTlsBuilder as TlsBuilder>::SigalgsList = [
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
        builder.set_cipher_list(&cipher.join(":"))?;
        builder.enable_signed_cert_timestamps();
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        builder.configure_add_cert_compression_alg(CertCompressionAlgorithm::Brotli)
    }
}

pub struct OkHttpTlsBuilder;

impl TlsBuilder for OkHttpTlsBuilder {
    type SigalgsList = [&'static str; 9];

    fn new(cipher: &[&str]) -> TlsResult<SslConnectorBuilder> {
        const SIGALGS_LIST: <OkHttpTlsBuilder as TlsBuilder>::SigalgsList = [
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
        builder.set_cipher_list(&cipher.join(":"))?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        Ok(builder)
    }
}

pub struct SafariTlsBuilder;

impl TlsBuilder for SafariTlsBuilder {
    type SigalgsList = [&'static str; 11];

    fn new(cipher: &[&str]) -> TlsResult<SslConnectorBuilder> {
        const SIGALGS_LIST: <SafariTlsBuilder as TlsBuilder>::SigalgsList = [
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
        builder.set_cipher_list(&cipher.join(":"))?;
        builder.set_curves(&[
            SslCurve::X25519,
            SslCurve::SECP256R1,
            SslCurve::SECP384R1,
            SslCurve::SECP521R1,
        ])?;
        builder.enable_signed_cert_timestamps();
        builder.set_min_proto_version(Some(SslVersion::TLS1))?;
        builder.configure_add_cert_compression_alg(CertCompressionAlgorithm::Zlib)
    }
}

impl TlsExtension for SslConnectorBuilder {
    fn configure_chrome_new_curves(mut self) -> TlsResult<SslConnectorBuilder> {
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
    ) -> TlsResult<SslConnectorBuilder> {
        if !certs_verification {
            self.set_verify(SslVerifyMode::NONE);
        } else {
            self.set_verify(SslVerifyMode::PEER);
        }
        Ok(self)
    }

    fn configure_alpn_protos(
        mut self,
        http_version: HttpVersionPref,
    ) -> TlsResult<SslConnectorBuilder> {
        match http_version {
            HttpVersionPref::Http1 => {
                self.set_alpn_protos(b"\x08http/1.1")?;
            }
            HttpVersionPref::Http2 => {
                self.set_alpn_protos(b"\x02h2")?;
            }
            HttpVersionPref::All => {
                self.set_alpn_protos(b"\x02h2\x08http/1.1")?;
            }
        }

        Ok(self)
    }

    fn configure_min_tls_version(
        mut self,
        min_tls_version: Option<Version>,
    ) -> TlsResult<SslConnectorBuilder> {
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
    ) -> TlsResult<SslConnectorBuilder> {
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

    fn configure_add_cert_compression_alg(
        self,
        cert_compression_alg: CertCompressionAlgorithm,
    ) -> TlsResult<SslConnectorBuilder> {
        unsafe {
            sv_handler(boring_sys::SSL_CTX_add_cert_compression_alg(
                self.as_ptr(),
                cert_compression_alg as _,
                cert_compression_alg.compression_fn(),
                cert_compression_alg.decompression_fn(),
            ))
            .map(|_| self)
        }
    }

    fn configure_ca_cert_file<P: AsRef<Path>>(
        mut self,
        ca_cert_file: Option<P>,
    ) -> TlsResult<SslConnectorBuilder> {
        if let Some(file) = ca_cert_file {
            self.set_ca_file(file)?;
        }

        Ok(self)
    }

    fn configure_permute_extensions(
        mut self,
        enable: bool,
        permute_extensions: bool,
    ) -> TlsResult<SslConnectorBuilder> {
        if !enable {
            return Ok(self);
        }

        self.set_permute_extensions(permute_extensions);
        Ok(self)
    }
}

impl TlsConnectExtension for ConnectConfiguration {
    fn configure_enable_ech_grease(
        &mut self,
        enable: bool,
        enable_ech_grease: bool,
    ) -> TlsResult<&mut ConnectConfiguration> {
        if !enable {
            return Ok(self);
        }

        unsafe { boring_sys::SSL_set_enable_ech_grease(self.as_ptr(), enable_ech_grease as _) }
        Ok(self)
    }

    fn configure_add_application_settings(
        &mut self,
        enable: bool,
        http_version: HttpVersionPref,
    ) -> TlsResult<&mut ConnectConfiguration> {
        if !enable {
            return Ok(self);
        }

        let (alpn, alpn_len) = match http_version {
            HttpVersionPref::Http1 => ("http/1.1", 8),
            HttpVersionPref::Http2 | HttpVersionPref::All => ("h2", 2),
        };

        unsafe {
            sv_handler(boring_sys::SSL_add_application_settings(
                self.as_ptr(),
                alpn.as_ptr(),
                alpn_len,
                std::ptr::null(),
                0,
            ))
            .map(|_| self)
        }
    }
}
