mod chrome;
mod edge;
mod okhttp;
pub mod profile;
mod safari;

use crate::connect::HttpConnector;
use boring::ssl::{ConnectConfiguration, SslConnectorBuilder};
use http::HeaderMap;
use profile::ClientProfile;
pub use profile::Impersonate;
use std::sync::Arc;

/// A wrapper around a `SslConnectorBuilder` that allows for additional settings.
#[derive(Clone)]
pub struct BoringTlsConnector(Arc<dyn Fn() -> SslConnectorBuilder + Send + Sync>);

impl BoringTlsConnector {
    /// Create a new `BoringTlsConnector` with the given function.
    pub fn new(inner: Arc<dyn Fn() -> SslConnectorBuilder + Send + Sync>) -> BoringTlsConnector {
        Self(inner)
    }

    /// Create a new `HttpsConnector` with the settings from the `ImpersonateContext`.
    pub(crate) fn create_https_connector(
        &self,
        context: &ImpersonateContext,
        http: HttpConnector,
    ) -> Result<hyper_boring::HttpsConnector<HttpConnector>, boring::error::ErrorStack> {
        let mut builder = self.0();
        alpn_and_cert_settings(context, &mut builder);

        let mut http = hyper_boring::HttpsConnector::with_connector(http, builder)?;
        let context = context.clone();
        http.set_callback(move |conf, _| {
            add_application_settings(conf, &context);
            Ok(())
        });

        Ok(http)
    }

    /// Create a new `SslConnector` with the settings from the `ImpersonateContext`.
    pub(crate) fn create_connect_configuration(
        &self,
        context: &ImpersonateContext,
    ) -> Result<ConnectConfiguration, boring::ssl::Error> {
        let mut builder = self.0();
        alpn_and_cert_settings(context, &mut builder);

        let mut conf = builder.build().configure()?;
        add_application_settings(&mut conf, context);
        Ok(conf)
    }
}

/// Configure the ALPN and certificate settings for the given `SslConnectorBuilder`.
fn alpn_and_cert_settings(context: &ImpersonateContext, builder: &mut SslConnectorBuilder) {
    if context.h2 {
        builder.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();
    } else {
        builder.set_alpn_protos(b"\x08http/1.1").unwrap();
    }

    if !context.certs_verification {
        builder.set_verify(boring::ssl::SslVerifyMode::NONE);
    }
}

/// Add application settings to the given `ConnectConfiguration`.
fn add_application_settings(conf: &mut ConnectConfiguration, ctx: &ImpersonateContext) {
    use foreign_types::ForeignTypeRef;
    match ctx.profile {
        ClientProfile::Chrome | ClientProfile::Edge => {
            // Enable random TLS extensions
            if ctx.permute_extensions {
                unsafe {
                    boring_sys::SSL_set_permute_extensions(conf.as_ptr(), 1);
                }
            }

            // Enable ECH grease
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
        _ => {}
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
    pub profile: ClientProfile,
    pub enable_ech_grease: bool,
    pub permute_extensions: bool,
    pub certs_verification: bool,
    pub h2: bool,
}
