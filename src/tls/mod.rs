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
mod profile;

pub(crate) use self::profile::tls_settings;
use crate::async_impl::client::HttpVersionPref;
use crate::connect::HttpConnector;
use crate::tls::extension::{SslConnectExtension, SslExtension};
use boring::ssl::{SslConnector, SslMethod};
use boring::{
    error::ErrorStack,
    ssl::{ConnectConfiguration, SslConnectorBuilder},
};
use connector::{HttpsConnector, HttpsLayer, HttpsLayerSettings};
use hyper::{PseudoOrder, SettingsOrder, StreamDependency};
pub use profile::Impersonate;
use profile::TypedImpersonate;
use std::any::Any;
use std::fmt::{self, Debug};

type TlsResult<T> = std::result::Result<T, ErrorStack>;

/// The TLS connector configuration.
#[derive(Clone)]
pub struct SslSettings {
    /// The client to impersonate.
    pub impersonate: Impersonate,
    /// The minimum TLS version to use.
    pub min_tls_version: Option<Version>,
    /// The maximum TLS version to use.
    pub max_tls_version: Option<Version>,
    /// Enable ECH grease.
    pub enable_ech_grease: bool,
    /// Permute extensions.
    pub permute_extensions: bool,
    /// Verify certificates.
    pub certs_verification: bool,
    /// Use a pre-shared key.
    pub pre_shared_key: bool,
    /// The HTTP version preference.
    pub http_version_pref: HttpVersionPref,
}

/// Connection settings
pub struct SslBuilderSettings {
    /// The SSL connector builder.
    pub ssl_builder: SslConnectorBuilder,
    /// Enable PSK.
    pub enable_psk: bool,
    /// HTTP/2 settings.
    pub http2: Http2Settings,
}

impl Debug for SslBuilderSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsSettings")
            .field("tls_builder", &self.ssl_builder.type_id())
            .field("http2", &self.http2)
            .finish()
    }
}

/// HTTP/2 settings.
#[derive(Debug)]
pub struct Http2Settings {
    /// The initial stream window size.
    pub initial_stream_window_size: Option<u32>,
    /// The initial connection window size.
    pub initial_connection_window_size: Option<u32>,
    /// The maximum concurrent streams.
    pub max_concurrent_streams: Option<u32>,
    /// The maximum header list size.
    pub max_header_list_size: Option<u32>,
    /// The header table size.
    pub header_table_size: Option<u32>,
    /// Enable push.
    pub enable_push: Option<bool>,
    /// The priority of the headers.
    pub headers_priority: Option<StreamDependency>,
    /// The pseudo header order.
    pub headers_pseudo_header: Option<[PseudoOrder; 4]>,
    /// The settings order.
    pub settings_order: Option<[SettingsOrder; 2]>,
}

impl Default for SslSettings {
    fn default() -> Self {
        Self {
            min_tls_version: None,
            max_tls_version: None,
            impersonate: Default::default(),
            enable_ech_grease: false,
            permute_extensions: false,
            certs_verification: true,
            pre_shared_key: false,
            http_version_pref: HttpVersionPref::All,
        }
    }
}

impl Debug for SslSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnector")
            .field("min_tls_version", &self.min_tls_version)
            .field("max_tls_version", &self.max_tls_version)
            .field("impersonate", &self.impersonate)
            .field("enable_ech_grease", &self.enable_ech_grease)
            .field("permute_extensions", &self.permute_extensions)
            .field("certs_verification", &self.certs_verification)
            .field("pre_shared_key", &self.pre_shared_key)
            .field("http_version_pref", &self.http_version_pref)
            .finish()
    }
}

/// A wrapper around a `SslConnectorBuilder` that allows for additional settings.
#[derive(Clone)]
pub struct TlsConnector {
    /// The TLS connector builder settings.
    settings: SslSettings,
    /// The TLS connector layer.
    layer: HttpsLayer,
}

impl TlsConnector {
    /// Create a new `BoringTlsConnector` with the given function.
    pub fn new(settings: SslSettings, ssl: Option<SslConnectorBuilder>) -> TlsResult<TlsConnector> {
        let ssl = match ssl {
            Some(ssl) => ssl,
            None => SslConnector::builder(SslMethod::tls_client())?,
        };
        Ok(Self {
            settings: settings.clone(),
            layer: Self::build_layer(settings, ssl)?,
        })
    }

    /// Create a new `HttpsConnector` with the settings from the `TlsContext`.
    #[inline]
    pub(crate) async fn new_connector(
        &self,
        http: HttpConnector,
    ) -> TlsResult<HttpsConnector<HttpConnector>> {
        // Create the `HttpsConnector` with the given `HttpConnector` and `HttpsLayer`.
        let mut http = HttpsConnector::with_connector_layer(http, self.layer.clone());

        // Set the callback to add application settings.
        let builder = self.settings.clone();
        http.set_callback(move |conf, _| configure_ssl_context(conf, &builder));

        Ok(http)
    }

    fn build_layer(settings: SslSettings, ssl: SslConnectorBuilder) -> TlsResult<HttpsLayer> {
        // Create the `SslConnectorBuilder` and configure it.
        let builder = ssl
            .configure_alpn_protos(&settings.http_version_pref)?
            .configure_cert_verification(settings.certs_verification)?
            .configure_min_tls_version(settings.min_tls_version)?
            .configure_max_tls_version(settings.max_tls_version)?;

        // Create the `HttpsLayerSettings` with the default session cache capacity.
        let settings = HttpsLayerSettings::builder()
            .session_cache(settings.pre_shared_key)
            .build();

        HttpsLayer::with_connector_and_settings(builder, settings)
    }
}

/// Add application settings to the given `ConnectConfiguration`.
fn configure_ssl_context(conf: &mut ConnectConfiguration, ctx: &SslSettings) -> TlsResult<()> {
    if matches!(
        ctx.impersonate.profile(),
        TypedImpersonate::Chrome | TypedImpersonate::Edge
    ) {
        conf.configure_permute_extensions(ctx.permute_extensions)?
            .configure_enable_ech_grease(ctx.enable_ech_grease)?
            .configure_add_application_settings(ctx.http_version_pref)?;
    }

    Ok(())
}

impl Debug for TlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoringTlsConnector")
            .field("builder", &self.settings.type_id())
            .field("connector", &self.type_id())
            .finish()
    }
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
