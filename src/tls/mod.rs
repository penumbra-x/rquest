//! TLS configuration
//!
//! By default, a `Client` will make use of BoringSSL for TLS.
//!
//! - Various parts of TLS can also be configured or even disabled on the
//!   `ClientBuilder`.

#![allow(missing_docs)]
mod cert_compression;
pub mod connector;
pub mod extension;
mod impersonate;
mod settings;

use crate::connect::HttpConnector;
use boring::{
    error::ErrorStack,
    ssl::{ConnectConfiguration, SslConnector, SslMethod},
};
use connector::{HttpsConnector, HttpsLayer, HttpsLayerSettings};
use extension::{SslConnectExtension, SslExtension};
pub use impersonate::{tls_settings, Impersonate};
pub use settings::{
    Http2Settings, ImpersonateSettings, SslExtensionSettings, SslImpersonateSettings, SslSettings,
};

type SslResult<T> = std::result::Result<T, ErrorStack>;

/// A wrapper around a `SslConnectorBuilder` that allows for additional settings.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct BoringTlsConnector {
    /// The TLS connector context settings.
    extension: SslExtensionSettings,
    /// The TLS connector layer.
    layer: HttpsLayer,
}

impl BoringTlsConnector {
    /// Create a new `BoringTlsConnector` with the given function.
    pub fn new(settings: SslSettings) -> SslResult<BoringTlsConnector> {
        Ok(Self {
            extension: settings.extension,
            layer: Self::build_layer(settings)?,
        })
    }

    /// Create a new `HttpsConnector` with the settings from the `TlsContext`.
    #[inline]
    pub(crate) async fn new_connector(
        &self,
        http: HttpConnector,
    ) -> SslResult<HttpsConnector<HttpConnector>> {
        // Create the `HttpsConnector` with the given `HttpConnector` and `HttpsLayer`.
        let mut http = HttpsConnector::with_connector_layer(http, self.layer.clone());

        // Set the callback to add application settings.
        let extension = self.extension;
        http.set_callback(move |conf, _| configure_ssl_context(conf, extension));

        Ok(http)
    }

    fn build_layer(settings: SslSettings) -> SslResult<HttpsLayer> {
        let ssl = match settings.ssl_builder {
            Some(ssl) => ssl,
            None => SslConnector::builder(SslMethod::tls_client())?,
        };

        // Create the `SslConnectorBuilder` and configure it.
        let builder = ssl
            .configure_ca_cert_file(settings.ca_cert_file)?
            .configure_cert_verification(settings.certs_verification)?
            .configure_alpn_protos(settings.extension.http_version_pref)?
            .configure_min_tls_version(settings.extension.min_tls_version)?
            .configure_max_tls_version(settings.extension.max_tls_version)?
            .configure_permute_extensions(
                settings.extension.application_settings,
                settings.extension.permute_extensions,
            )?;

        // Create the `HttpsLayerSettings` with the default session cache capacity.
        let settings = HttpsLayerSettings::builder()
            .session_cache(
                settings.extension.application_settings && settings.extension.pre_shared_key,
            )
            .build();

        HttpsLayer::with_connector_and_settings(builder, settings)
    }
}

/// Add application settings to the given `ConnectConfiguration`.
fn configure_ssl_context(
    conf: &mut ConnectConfiguration,
    ext: SslExtensionSettings,
) -> SslResult<()> {
    conf.configure_enable_ech_grease(ext.application_settings, ext.enable_ech_grease)?
        .configure_add_application_settings(ext.application_settings, ext.http_version_pref)?
        .set_use_server_name_indication(ext.tls_sni);
    Ok(())
}
/// A TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(InnerVersion);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
enum InnerVersion {
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

// These could perhaps be From/TryFrom implementations, but those would be
// part of the public API so let's be careful
impl Version {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: Version = Version(InnerVersion::Tls1_0);
    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: Version = Version(InnerVersion::Tls1_1);
    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: Version = Version(InnerVersion::Tls1_2);
    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: Version = Version(InnerVersion::Tls1_3);
}

/// Hyper extension carrying extra TLS layer information.
/// Made available to clients on responses when `tls_info` is set.
#[derive(Clone)]
pub struct TlsInfo {
    pub(crate) peer_certificate: Option<Vec<u8>>,
}

impl TlsInfo {
    /// Get the DER encoded leaf certificate of the peer.
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_certificate.as_ref().map(|der| &der[..])
    }
}

impl std::fmt::Debug for TlsInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("TlsInfo").finish()
    }
}
