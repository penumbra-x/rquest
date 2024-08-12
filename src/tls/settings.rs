use super::{
    impersonate::{Impersonate, TypedImpersonate},
    Version,
};
use crate::async_impl::client::HttpVersionPref;
use boring::ssl::SslConnectorBuilder;
use hyper::{PseudoOrder, SettingsOrder, StreamDependency, StreamId};
use std::fmt::Debug;
use std::{any::Any, path::PathBuf};
use PseudoOrder::*;
use SettingsOrder::*;
use TypedImpersonate::*;

/// The TLS connector configuration.
#[derive(Debug)]
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
    /// CA certificates file path.
    pub ca_cert_file: Option<PathBuf>,
    /// Use a pre-shared key.
    pub pre_shared_key: bool,
    /// The HTTP version preference.
    pub http_version_pref: HttpVersionPref,
}

/// The TLS context settings.
#[derive(Debug, Clone, Copy)]
pub struct SslContextSettings {
    /// The client to impersonate.
    pub typed: TypedImpersonate,
    /// Enable ECH grease.
    pub enable_ech_grease: bool,
    /// Permute extensions.
    pub permute_extensions: bool,
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
    pub headers_pseudo_order: Option<[PseudoOrder; 4]>,
    /// The settings order.
    pub settings_order: Option<[SettingsOrder; 2]>,
}

/// Impersonate extension settings.
#[derive(Debug)]
pub struct ImpersonateSettings {
    /// Enable pre-shared key.
    pub pre_share_key: bool,
    /// Headers frame priority.
    pub headers_priority: Option<StreamDependency>,
    /// Headers frame pseudo order.
    pub headers_pseudo_order: Option<[PseudoOrder; 4]>,
    /// Settings frame order.
    pub settings_order: Option<[SettingsOrder; 2]>,
}

// ============= SslBuilderSettings impls =============

impl Debug for SslBuilderSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsSettings")
            .field("tls_builder", &self.ssl_builder.type_id())
            .field("http2", &self.http2)
            .finish()
    }
}

// ============= SslSettings impls =============

impl Default for SslSettings {
    fn default() -> Self {
        Self {
            min_tls_version: None,
            max_tls_version: None,
            impersonate: Default::default(),
            enable_ech_grease: false,
            permute_extensions: false,
            certs_verification: true,
            ca_cert_file: None,
            pre_shared_key: false,
            http_version_pref: HttpVersionPref::All,
        }
    }
}

// ============= SslContextSettings impls =============
impl From<&SslSettings> for SslContextSettings {
    fn from(settings: &SslSettings) -> Self {
        Self {
            typed: settings.impersonate.typed(),
            enable_ech_grease: settings.enable_ech_grease,
            permute_extensions: settings.permute_extensions,
            http_version_pref: settings.http_version_pref,
        }
    }
}

// ============= ImpersonateSettings impls =============
impl From<Impersonate> for ImpersonateSettings {
    fn from(impersonate: Impersonate) -> Self {
        let typed = impersonate.typed();

        // The headers frame priority.
        let headers_priority = {
            let (weight, exclusive) = match typed {
                TypedImpersonate::Safari => (254, false),
                _ => (255, true),
            };
            StreamDependency::new(StreamId::zero(), weight, exclusive)
        };

        // The headers frame pseudo order.
        let headers_pseudo_order = {
            match typed {
                Chrome | Edge => [Method, Authority, Scheme, Path],
                OkHttp => [Method, Path, Authority, Scheme],
                Safari => [Method, Scheme, Path, Authority],
            }
        };

        // The settings frame order.
        let settings_order = {
            match typed {
                TypedImpersonate::Safari => [InitialWindowSize, MaxConcurrentStreams],
                _ => [MaxConcurrentStreams, InitialWindowSize],
            }
        };

        Self {
            pre_share_key: impersonate.pre_share_key(),
            headers_priority: Some(headers_priority),
            headers_pseudo_order: Some(headers_pseudo_order),
            settings_order: Some(settings_order),
        }
    }
}
