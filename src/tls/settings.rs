#![allow(missing_debug_implementations)]
use super::{impersonate::Impersonate, Version};
use crate::client::client::HttpVersionPref;
use boring::ssl::SslConnectorBuilder;
use hyper::{PseudoOrder, SettingsOrder};
use std::path::PathBuf;
use typed_builder::TypedBuilder;
use Impersonate::*;
use PseudoOrder::*;
use SettingsOrder::*;

/// The TLS connector configuration.
pub struct Tls {
    /// Verify certificates.
    pub(crate) certs_verification: bool,

    /// CA certificates file path.
    pub(crate) ca_cert_file: Option<PathBuf>,

    /// The Tls extension settings.
    pub(crate) extension: TlsExtensionSettings,

    /// The SSL connector builder.
    pub(crate) builder: Option<SslConnectorBuilder>,
}

/// The TLS settings.
#[derive(TypedBuilder)]
pub struct TlsSettings {
    /// The SSL connector builder.
    pub(crate) builder: SslConnectorBuilder,

    /// TLS extension settings.
    pub(crate) extension: TlsExtensionSettings,

    /// HTTP/2 settings.
    pub(crate) http2: Http2FrameSettings,
}

/// Extension settings.
#[derive(Clone, Copy, TypedBuilder)]
pub struct TlsExtensionSettings {
    #[builder(default = true)]
    pub(crate) tls_sni: bool,

    /// The HTTP version preference (setting alpn).
    #[builder(default = HttpVersionPref::All)]
    pub(crate) http_version_pref: HttpVersionPref,

    /// The minimum TLS version to use.
    #[builder(default)]
    pub(crate) min_tls_version: Option<Version>,

    /// The maximum TLS version to use.
    #[builder(default)]
    pub(crate) max_tls_version: Option<Version>,

    /// Enable application settings.
    #[builder(default = true)]
    pub(crate) application_settings: bool,

    /// Enable PSK.
    #[builder(default = true)]
    pub(crate) pre_shared_key: bool,

    /// Enable ECH grease.
    #[builder(default = true)]
    pub(crate) enable_ech_grease: bool,

    /// Permute extensions.
    #[builder(default = true)]
    pub(crate) permute_extensions: bool,
}

/// HTTP/2 settings.
#[derive(TypedBuilder)]
pub struct Http2FrameSettings {
    /// The initial stream window size.
    #[builder(default, setter(strip_option))]
    pub(crate) initial_stream_window_size: Option<u32>,

    /// The initial connection window size.
    #[builder(default, setter(strip_option))]
    pub(crate) initial_connection_window_size: Option<u32>,

    /// The maximum concurrent streams.
    #[builder(default, setter(strip_option))]
    pub(crate) max_concurrent_streams: Option<u32>,

    /// The maximum header list size.
    #[builder(default, setter(strip_option))]
    pub(crate) max_header_list_size: Option<u32>,

    /// The header table size.
    #[builder(default, setter(strip_option))]
    pub(crate) header_table_size: Option<u32>,

    /// Enable push.
    #[builder(default)]
    pub(crate) enable_push: Option<bool>,

    /// The priority of the headers.
    #[builder(default, setter(strip_option))]
    pub(crate) headers_priority: Option<(u32, u8, bool)>,

    /// The pseudo header order.
    #[builder(default, setter(strip_option))]
    pub(crate) headers_pseudo_order: Option<[PseudoOrder; 4]>,

    /// The settings order.
    #[builder(default, setter(strip_option))]
    pub(crate) settings_order: Option<[SettingsOrder; 2]>,
}

/// Impersonate extension settings.
pub struct ImpersonateSettings {
    /// TLS extension settings.
    pub(crate) extension: TlsExtensionSettings,

    /// Headers frame priority.
    pub(crate) headers_priority: Option<(u32, u8, bool)>,

    /// Headers frame pseudo order.
    pub(crate) headers_pseudo_order: Option<[PseudoOrder; 4]>,

    /// Settings frame order.
    pub(crate) settings_order: Option<[SettingsOrder; 2]>,
}

// ============= SslSettings impls =============

impl Default for Tls {
    fn default() -> Self {
        Self {
            certs_verification: true,
            ca_cert_file: None,
            extension: TlsExtensionSettings {
                tls_sni: true,
                http_version_pref: HttpVersionPref::All,
                min_tls_version: None,
                max_tls_version: None,
                pre_shared_key: false,
                application_settings: false,
                enable_ech_grease: false,
                permute_extensions: false,
            },
            builder: None,
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
            | Chrome123 | Chrome124 | Chrome126 | Chrome127 | Chrome128 => 0,

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
                | Chrome128
                | Edge122
                | Edge127
        );

        // The headers frame priority.
        let headers_priority = {
            let set = match cluster {
                0..=2 => Some((255, true)),
                3 => Some((254, false)),
                _ => None,
            };

            set.map(|(stream_id, exclusive)| (0, stream_id, exclusive))
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
                0..=2 => Some([MaxConcurrentStreams, InitialWindowSize]),
                3 => Some([InitialWindowSize, MaxConcurrentStreams]),
                _ => None,
            }
        };

        Self {
            extension: TlsExtensionSettings::builder()
                .tls_sni(true)
                .http_version_pref(HttpVersionPref::All)
                .max_tls_version(None)
                .min_tls_version(None)
                .application_settings(application_settings)
                .pre_shared_key(pre_shared_key)
                .permute_extensions(false)
                .enable_ech_grease(false)
                .build(),
            headers_priority,
            headers_pseudo_order,
            settings_order,
        }
    }
}
