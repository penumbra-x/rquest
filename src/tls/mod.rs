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

use crate::connect::HttpConnector;
use crate::tls::extension::{SslConnectExtension, SslExtension};
use antidote::Mutex;
#[cfg(feature = "socks")]
use boring::ssl::Ssl;
use boring::{
    error::ErrorStack,
    ssl::{ConnectConfiguration, SslConnectorBuilder},
};
use hyper_boring::{HttpsConnector, HttpsLayerSettings, SessionCache};
pub(crate) use profile::configure_impersonate;
use profile::ClientProfile;
pub use profile::{Http2Settings, Impersonate, ImpersonateSettings};
use std::any::Any;
use std::fmt::{self, Debug};
use std::sync::Arc;
use tokio::sync::OnceCell;

type Builder = dyn Fn() -> Result<SslConnectorBuilder, ErrorStack> + Send + Sync;

/// Context for impersonating a client.
#[derive(Clone)]
pub(crate) struct ImpersonateContext {
    pub impersonate: Impersonate,
    pub enable_ech_grease: bool,
    pub permute_extensions: bool,
    pub certs_verification: bool,
    pub pre_shared_key: bool,
    pub h2: bool,
}

const DEFAULT_SESSION_CACHE_CAPACITY: usize = 8;

type Session = Arc<Mutex<SessionCache>>;

/// A wrapper around a `SslConnectorBuilder` that allows for additional settings.
#[derive(Clone)]
pub struct BoringTlsConnector {
    /// The inner `SslConnectorBuilder`.
    builder: Arc<Builder>,
    /// The cached `HttpsConnector` sessions.
    session: Arc<OnceCell<Session>>,
}

impl BoringTlsConnector {
    /// Create a new `BoringTlsConnector` with the given function.
    pub fn new<F>(builder: F) -> BoringTlsConnector
    where
        F: Fn() -> Result<SslConnectorBuilder, ErrorStack> + Send + Sync + 'static,
    {
        Self {
            builder: Arc::new(builder),
            session: Arc::new(OnceCell::new()),
        }
    }

    /// Create a new `HttpsConnector` with the settings from the `ImpersonateContext`.
    #[inline]
    pub(crate) async fn create_connector(
        &self,
        context: &ImpersonateContext,
        http: HttpConnector,
    ) -> Result<HttpsConnector<HttpConnector>, ErrorStack> {
        // Create the `SslConnectorBuilder` and configure it.
        let builder = (self.builder)()?
            .configure_alpn_protos(context.h2)?
            .configure_cert_verification(context.certs_verification)?;

        // Check if the PSK extension should be enabled.
        let psk_extension = matches!(
            context.impersonate,
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

        // Create the `HttpsConnector` with the given settings.
        let mut http = if psk_extension || context.pre_shared_key {
            // Initialize the session cache.
            let session = self
                .session
                .get_or_init(|| async {
                    Session::new(Mutex::new(SessionCache::with_capacity(
                        DEFAULT_SESSION_CACHE_CAPACITY,
                    )))
                })
                .await
                .clone();

            HttpsConnector::with_connector_and_settings(
                http,
                builder,
                HttpsLayerSettings::builder()
                    .session_cache_capacity(DEFAULT_SESSION_CACHE_CAPACITY)
                    .session_cache(session)
                    .build(),
            )?
        } else {
            HttpsConnector::with_connector(http, builder)?
        };

        // Set the callback to add application settings.
        let context = context.clone();
        http.set_callback(move |conf, _| {
            configure_ssl_context(conf, &context);
            Ok(())
        });
        Ok(http)
    }

    /// Create a new `SslConnector` with the settings from the `ImpersonateContext`.
    #[cfg(feature = "socks")]
    #[inline]
    pub(crate) async fn create_ssl(
        &self,
        context: &ImpersonateContext,
        http: HttpConnector,
        uri: &http::uri::Uri,
        host: &str,
    ) -> Result<Ssl, ErrorStack> {
        let connector = self.create_connector(context, http).await?;
        connector.setup_ssl(uri, host)
    }
}

/// Add application settings to the given `ConnectConfiguration`.
fn configure_ssl_context(conf: &mut ConnectConfiguration, ctx: &ImpersonateContext) {
    if matches!(
        ctx.impersonate.profile(),
        ClientProfile::Chrome | ClientProfile::Edge
    ) {
        conf.configure_permute_extensions(ctx.permute_extensions)
            .configure_enable_ech_grease(ctx.enable_ech_grease)
            .configure_add_application_settings(ctx.h2);
    }
}

impl Debug for BoringTlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoringTlsConnector")
            .field("builder", &self.builder.type_id())
            .field("session", &self.session.type_id())
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

pub(crate) enum TlsBackend {
    #[cfg(feature = "__boring")]
    BoringTls(BoringTlsConnector),
    #[cfg(not(feature = "__boring"))]
    UnknownPreconfigured,
}

impl fmt::Debug for TlsBackend {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            #[cfg(feature = "__boring")]
            TlsBackend::BoringTls(_) => write!(f, "BoringTls"),
            #[cfg(not(feature = "__boring"))]
            TlsBackend::UnknownPreconfigured => write!(f, "UnknownPreconfigured"),
        }
    }
}

impl Default for TlsBackend {
    fn default() -> TlsBackend {
        #[cfg(feature = "__boring")]
        {
            use boring::ssl::{SslConnector, SslMethod};
            TlsBackend::BoringTls(BoringTlsConnector::new(|| {
                SslConnector::builder(SslMethod::tls())
            }))
        }
        #[cfg(not(feature = "__boring"))]
        {
            TlsBackend::UnknownPreconfigured
        }
    }
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
