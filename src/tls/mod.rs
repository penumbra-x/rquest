//! TLS configuration
//!
//! By default, a `Client` will make use of system-native transport layer
//! security to connect to HTTPS destinations. This means schannel on Windows,
//! Security-Framework on macOS, and OpenSSL on Linux.
//!
//! - Various parts of TLS can also be configured or even disabled on the
//!   `ClientBuilder`.

mod chrome;
mod edge;
pub mod extension;
mod okhttp;
mod profile;
mod safari;

pub(crate) use self::profile::connect_settings;
use crate::async_impl::client::HttpVersionPref;
use crate::connect::HttpConnector;
use crate::tls::extension::{SslConnectExtension, SslExtension};
use boring::ssl::{SslConnector, SslMethod};
use boring::{
    error::ErrorStack,
    ssl::{ConnectConfiguration, SslConnectorBuilder},
};
use hyper_boring::{HttpsConnector, HttpsLayer, HttpsLayerSettings};
use profile::ClientProfile;
pub use profile::{ConnectSettings, Http2Settings, Impersonate};
use std::any::Any;
use std::fmt::{self, Debug};
use std::sync::Arc;
use tokio::sync::OnceCell;

/// Default session cache capacity.
const DEFAULT_SESSION_CACHE_CAPACITY: usize = 8;

/// A TLS connector builder.
type Builder = dyn Fn() -> Result<SslConnectorBuilder, ErrorStack> + Send + Sync + 'static;

/// The TLS connector configuration.
#[derive(Clone)]
pub struct TlsConnectorBuilder {
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
    /// The SSL connector builder.
    pub builder: Arc<Builder>,
}

impl Default for TlsConnectorBuilder {
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
            builder: Arc::new(|| SslConnector::builder(SslMethod::tls())),
        }
    }
}

impl Debug for TlsConnectorBuilder {
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
            .field("builder", &self.builder.type_id())
            .finish()
    }
}

/// A wrapper around a `SslConnectorBuilder` that allows for additional settings.
#[derive(Clone)]
pub struct TlsConnector {
    /// The inner `SslConnectorBuilder`.
    builder: TlsConnectorBuilder,
    /// The TLS connector layer.
    inner: Arc<OnceCell<HttpsLayer>>,
}

impl TlsConnector {
    /// Create a new `BoringTlsConnector` with the given function.
    pub fn new(builder: TlsConnectorBuilder) -> TlsConnector {
        Self {
            builder,
            inner: Arc::new(OnceCell::new()),
        }
    }

    /// Create a new `HttpsConnector` with the settings from the `TlsContext`.
    #[inline]
    pub(crate) async fn new_connector(
        &self,
        http: HttpConnector,
    ) -> Result<HttpsConnector<HttpConnector>, ErrorStack> {
        // Get the `HttpsLayer` or create it if it doesn't exist.
        let layer = self
            .inner
            .get_or_try_init(|| self.build_layer())
            .await
            .map(Clone::clone)?;

        // Create the `HttpsConnector` with the given `HttpConnector` and `HttpsLayer`.
        let mut http = HttpsConnector::with_connector_layer(http, layer);

        // Set the callback to add application settings.
        let builder = self.builder.clone();
        http.set_callback(move |conf, _| {
            configure_ssl_context(conf, &builder);
            Ok(())
        });

        Ok(http)
    }

    async fn build_layer(&self) -> Result<HttpsLayer, ErrorStack> {
        let tls = &self.builder;
        // Create the `SslConnectorBuilder` and configure it.
        let builder = (tls.builder)()?
            .configure_alpn_protos(&tls.http_version_pref)?
            .configure_cert_verification(tls.certs_verification)?
            .configure_min_tls_version(tls.min_tls_version)?
            .configure_max_tls_version(tls.max_tls_version)?;

        // Check if the PSK extension should be enabled.
        let psk_extension = matches!(
            tls.impersonate,
            Impersonate::Chrome116
                | Impersonate::Chrome117
                | Impersonate::Chrome120
                | Impersonate::Chrome123
                | Impersonate::Chrome124
                | Impersonate::Chrome126
                | Impersonate::Chrome127
                | Impersonate::Edge122
                | Impersonate::Edge127
        );

        if psk_extension || tls.pre_shared_key {
            HttpsLayer::with_connector_and_settings(
                builder,
                HttpsLayerSettings::builder()
                    .session_cache_capacity(DEFAULT_SESSION_CACHE_CAPACITY)
                    .build(),
            )
        } else {
            HttpsLayer::with_connector(builder)
        }
    }
}

/// Add application settings to the given `ConnectConfiguration`.
fn configure_ssl_context(conf: &mut ConnectConfiguration, ctx: &TlsConnectorBuilder) {
    if matches!(
        ctx.impersonate.profile(),
        ClientProfile::Chrome | ClientProfile::Edge
    ) {
        conf.configure_permute_extensions(ctx.permute_extensions)
            .configure_enable_ech_grease(ctx.enable_ech_grease)
            .configure_add_application_settings(ctx.http_version_pref);
    }
}

impl Debug for TlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoringTlsConnector")
            .field("builder", &self.builder.type_id())
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
