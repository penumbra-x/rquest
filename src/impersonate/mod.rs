mod chrome;
mod curves;
mod edge;
mod okhttp;
pub mod profile;
mod safari;

use crate::connect::HttpConnector;
use antidote::Mutex;
use boring::{
    error::ErrorStack,
    ssl::{ConnectConfiguration, SslConnectorBuilder},
};
use http::HeaderMap;
use hyper_boring::{HttpsConnector, SessionCache};
use profile::ClientProfile;
pub use profile::Impersonate;
use std::sync::Arc;

type Builder = dyn Fn() -> Result<SslConnectorBuilder, ErrorStack> + Send + Sync;

/// A wrapper around a `SslConnectorBuilder` that allows for additional settings.
#[derive(Clone)]
pub struct BoringTlsConnector {
    /// The inner `` function.
    builder: Arc<Builder>,
    /// The cached `HttpsConnector`.
    session: Arc<Mutex<SessionCache>>,
}

impl BoringTlsConnector {
    /// Create a new `BoringTlsConnector` with the given function.
    pub fn new<F>(builder: F) -> BoringTlsConnector
    where
        F: Fn() -> Result<SslConnectorBuilder, ErrorStack> + Send + Sync + 'static,
    {
        Self {
            builder: Arc::new(builder),
            session: Arc::new(Mutex::new(SessionCache::new())),
        }
    }

    /// Create a new `HttpsConnector` with the settings from the `ImpersonateContext`.
    #[inline]
    pub(crate) async fn create_https_connector(
        &self,
        context: &ImpersonateContext,
        http: HttpConnector,
    ) -> Result<HttpsConnector<HttpConnector>, ErrorStack> {
        let mut builder = (self.builder)()?;
        set_alpn_proto(&mut builder, context.h2);
        set_cert_verification(&mut builder, context.certs_verification);
        self.create_connector(context, http, builder)
    }

    /// Create a new `SslConnector` with the settings from the `ImpersonateContext`.
    #[cfg(feature = "socks")]
    #[inline]
    pub(crate) async fn create_connector_configuration(
        &self,
        context: &ImpersonateContext,
        http: HttpConnector,
        uri: &http::uri::Uri,
        host: &str,
    ) -> Result<ConnectConfiguration, ErrorStack> {
        let connector = self.create_https_connector(context, http).await?;
        let mut conf = connector.configure_and_setup(uri, host)?;
        set_add_application_settings(&mut conf, context);
        Ok(conf)
    }

    /// Create a new `HttpsConnector` with the settings from the `ImpersonateContext`.
    fn create_connector(
        &self,
        context: &ImpersonateContext,
        http: HttpConnector,
        builder: SslConnectorBuilder,
    ) -> Result<HttpsConnector<HttpConnector>, ErrorStack> {
        let psk_extension = matches!(
            context.impersonate,
            Impersonate::Chrome117
                | Impersonate::Chrome120
                | Impersonate::Chrome123
                | Impersonate::Chrome124
                | Impersonate::Chrome126
                | Impersonate::Edge122
                | Impersonate::Edge127
        );

        let mut http = if psk_extension {
            HttpsConnector::with_connector_and_cache(http, builder, self.session.clone())?
        } else {
            HttpsConnector::with_connector(http, builder)?
        };

        set_callback(&mut http, context.clone());
        Ok(http)
    }
}

/// Configure the callback for the given `HttpsConnector`.
fn set_callback(http: &mut HttpsConnector<HttpConnector>, context: ImpersonateContext) {
    http.set_callback(move |conf, _| Ok(set_add_application_settings(conf, &context)));
}

/// Configure the ALPN and certificate settings for the given `SslConnectorBuilder`.
fn set_alpn_proto(builder: &mut SslConnectorBuilder, h2: bool) {
    if h2 {
        builder.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();
    } else {
        builder.set_alpn_protos(b"\x08http/1.1").unwrap();
    }
}

/// Configure the certificate verification for the given `SslConnectorBuilder`.
fn set_cert_verification(builder: &mut SslConnectorBuilder, certs_verification: bool) {
    if !certs_verification {
        builder.set_verify(boring::ssl::SslVerifyMode::NONE);
    }
}

/// Add application settings to the given `ConnectConfiguration`.
fn set_add_application_settings(conf: &mut ConnectConfiguration, ctx: &ImpersonateContext) {
    match ctx.impersonate.profile() {
        ClientProfile::Chrome | ClientProfile::Edge => {
            configure_tls_extensions(conf, ctx);
        }
        _ => {}
    }
}

/// Configure the TLS extensions for the given `ConnectConfiguration`.
fn configure_tls_extensions(conf: &mut ConnectConfiguration, ctx: &ImpersonateContext) {
    use foreign_types::ForeignTypeRef;
    if ctx.permute_extensions {
        unsafe {
            boring_sys::SSL_set_permute_extensions(conf.as_ptr(), 1);
        }
    }

    if ctx.enable_ech_grease {
        unsafe { boring_sys::SSL_set_enable_ech_grease(conf.as_ptr(), 1) }
    }

    if ctx.h2 {
        const ALPN_H2: &str = "h2";
        const ALPN_H2_LENGTH: usize = 2;
        unsafe {
            boring_sys::SSL_add_application_settings(
                conf.as_ptr(),
                ALPN_H2.as_ptr(),
                ALPN_H2_LENGTH,
                std::ptr::null(),
                0,
            );
        };
    }
}

/// Create a new `BoringTlsConnector` with the given function.
pub(crate) struct ImpersonateSettings {
    pub tls_connector: BoringTlsConnector,
    pub http2: Http2Data,
    pub headers: HeaderMap,
    pub gzip: bool,
    pub brotli: bool,
}

/// HTTP/2 settings.
pub(crate) struct Http2Data {
    pub initial_stream_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub max_concurrent_streams: Option<u32>,
    pub max_header_list_size: Option<u32>,
    pub header_table_size: Option<u32>,
    pub enable_push: Option<bool>,
}

/// Context for impersonating a client.
#[derive(Clone)]
pub(crate) struct ImpersonateContext {
    pub impersonate: Impersonate,
    pub enable_ech_grease: bool,
    pub permute_extensions: bool,
    pub certs_verification: bool,
    pub h2: bool,
}
