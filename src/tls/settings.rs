#![allow(missing_debug_implementations)]
use super::{impersonate::Impersonate, Version};
use crate::async_impl::client::HttpVersionPref;
use boring::ssl::SslConnectorBuilder;
use hyper::{PseudoOrder, SettingsOrder, StreamDependency, StreamId};
use std::path::PathBuf;
use Impersonate::*;
use PseudoOrder::*;
use SettingsOrder::*;

/// The TLS connector configuration.
pub struct SslSettings {
    /// Verify certificates.
    pub certs_verification: bool,
    /// CA certificates file path.
    pub ca_cert_file: Option<PathBuf>,
    /// The Tls extension settings.
    pub extension: SslExtensionSettings,
    /// The SSL connector builder.
    pub ssl_builder: Option<SslConnectorBuilder>,
}

/// Connection settings
pub struct SslImpersonateSettings {
    /// The SSL connector builder.
    pub ssl_builder: SslConnectorBuilder,
    /// TLS extension settings.
    pub extension: SslExtensionSettings,
    /// HTTP/2 settings.
    pub http2: Http2Settings,
}

/// Extension settings.
#[derive(Clone, Copy)]
pub struct SslExtensionSettings {
    pub tls_sni: bool,
    /// The HTTP version preference (setting alpn).
    pub http_version_pref: HttpVersionPref,
    /// The minimum TLS version to use.
    pub min_tls_version: Option<Version>,
    /// The maximum TLS version to use.
    pub max_tls_version: Option<Version>,
    /// Enable application settings.
    pub application_settings: bool,
    /// Enable PSK.
    pub pre_shared_key: bool,
    /// Enable ECH grease.
    pub enable_ech_grease: bool,
    /// Permute extensions.
    pub permute_extensions: bool,
}

/// HTTP/2 settings.
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
pub struct ImpersonateSettings {
    /// TLS extension settings.
    pub extension: SslExtensionSettings,
    /// Headers frame priority.
    pub headers_priority: Option<StreamDependency>,
    /// Headers frame pseudo order.
    pub headers_pseudo_order: Option<[PseudoOrder; 4]>,
    /// Settings frame order.
    pub settings_order: Option<[SettingsOrder; 2]>,
}

// ============= SslSettings impls =============

impl Default for SslSettings {
    fn default() -> Self {
        Self {
            certs_verification: true,
            ca_cert_file: None,
            extension: SslExtensionSettings {
                tls_sni: true,
                http_version_pref: HttpVersionPref::All,
                min_tls_version: None,
                max_tls_version: None,
                pre_shared_key: false,
                application_settings: false,
                enable_ech_grease: false,
                permute_extensions: false,
            },
            ssl_builder: None,
        }
    }
}

// ============= ImpersonateSettings impls =============
impl From<Impersonate> for ImpersonateSettings {
    fn from(impersonate: Impersonate) -> Self {
        let cluster = match impersonate {
            // Chrome
            Chrome100 | Chrome101 | Chrome104 | Chrome105 | Chrome106 | Chrome107 | Chrome108
            | Chrome109 | Chrome114 | Chrome116 | Chrome117 | Chrome118 | Chrome119 | Chrome120
            | Chrome123 | Chrome124 | Chrome126 | Chrome127 => 0,

            // Edge
            Edge101 | Edge122 | Edge127 => 1,

            // OkHttp
            OkHttp3_9 | OkHttp3_11 | OkHttp3_13 | OkHttp3_14 | OkHttp4_9 | OkHttp4_10 | OkHttp5 => {
                2
            }

            // Safari
            SafariIos17_2 | SafariIos16_5 | SafariIos17_4_1 | Safari15_3 | Safari15_5
            | Safari15_6_1 | Safari16 | Safari16_5 | Safari17_0 | Safari17_2_1 | Safari17_4_1
            | Safari17_5 => 3,
        };

        // Enable application settings.
        let application_settings = matches!(cluster, 0 | 1);

        // Enable pre-shared key.
        let pre_shared_key = matches!(
            impersonate,
            Chrome116
                | Chrome117
                | Chrome120
                | Chrome123
                | Chrome124
                | Chrome126
                | Chrome127
                | Edge122
                | Edge127
        );

        // The headers frame priority.
        let headers_priority = {
            let set = match cluster {
                0 | 1 | 2 => Some((255, true)),
                3 => Some((254, false)),
                _ => None,
            };

            set.map_or(None, |(weight, exclusive)| {
                Some(StreamDependency::new(StreamId::zero(), weight, exclusive))
            })
        };

        // The headers frame pseudo order.
        let headers_pseudo_order = {
            match cluster {
                0 | 1 => Some([Method, Authority, Scheme, Path]),
                2 => Some([Method, Path, Authority, Scheme]),
                3 => Some([Method, Scheme, Path, Authority]),
                _ => None,
            }
        };

        // The settings frame order.
        let settings_order = {
            match cluster {
                0 | 1 | 2 => Some([MaxConcurrentStreams, InitialWindowSize]),
                3 => Some([InitialWindowSize, MaxConcurrentStreams]),
                _ => None,
            }
        };

        Self {
            extension: SslExtensionSettings {
                tls_sni: true,
                http_version_pref: HttpVersionPref::All,
                min_tls_version: None,
                max_tls_version: None,
                application_settings,
                pre_shared_key,
                enable_ech_grease: false,
                permute_extensions: false,
            },
            headers_priority,
            headers_pseudo_order,
            settings_order,
        }
    }
}
