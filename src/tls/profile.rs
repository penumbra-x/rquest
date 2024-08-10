#![allow(missing_docs)]
use crate::tls::{chrome, edge, okhttp, safari};
use http::HeaderMap;
use hyper::AgentProfile;
use std::{any::Any, fmt::Debug, str::FromStr, sync::Arc};

macro_rules! impersonate_match {
    ($ver:expr, $headers:expr, $($variant:pat => $path:path),+) => {
        match $ver {
            $(
                $variant => $path($headers),
            )+
        }
    }
}

/// Get the connection settings for the given impersonate version
pub fn connect_settings(ver: Impersonate, headers: &mut HeaderMap) -> ConnectSettings {
    impersonate_match!(
        ver,
        headers,
        Impersonate::Chrome100 => chrome::v100::get_settings,
        Impersonate::Chrome101 => chrome::v101::get_settings,
        Impersonate::Chrome104 => chrome::v104::get_settings,
        Impersonate::Chrome105 => chrome::v105::get_settings,
        Impersonate::Chrome106 => chrome::v106::get_settings,
        Impersonate::Chrome107 => chrome::v107::get_settings,
        Impersonate::Chrome108 => chrome::v108::get_settings,
        Impersonate::Chrome109 => chrome::v109::get_settings,
        Impersonate::Chrome114 => chrome::v114::get_settings,
        Impersonate::Chrome116 => chrome::v116::get_settings,
        Impersonate::Chrome117 => chrome::v117::get_settings,
        Impersonate::Chrome118 => chrome::v118::get_settings,
        Impersonate::Chrome119 => chrome::v119::get_settings,
        Impersonate::Chrome120 => chrome::v120::get_settings,
        Impersonate::Chrome123 => chrome::v123::get_settings,
        Impersonate::Chrome124 => chrome::v124::get_settings,
        Impersonate::Chrome126 => chrome::v126::get_settings,
        Impersonate::Chrome127 => chrome::v127::get_settings,

        Impersonate::SafariIos17_2 => safari::safari_ios_17_2::get_settings,
        Impersonate::SafariIos17_4_1 => safari::safari_ios_17_4_1::get_settings,
        Impersonate::SafariIos16_5 => safari::safari_ios_16_5::get_settings,
        Impersonate::Safari15_3 => safari::safari15_3::get_settings,
        Impersonate::Safari15_5 => safari::safari15_5::get_settings,
        Impersonate::Safari15_6_1 => safari::safari15_6_1::get_settings,
        Impersonate::Safari16 => safari::safari16::get_settings,
        Impersonate::Safari16_5 => safari::safari16_5::get_settings,
        Impersonate::Safari17_0 => safari::safari17_0::get_settings,
        Impersonate::Safari17_2_1 => safari::safari17_2_1::get_settings,
        Impersonate::Safari17_4_1 => safari::safari17_4_1::get_settings,
        Impersonate::Safari17_5 => safari::safari17_5::get_settings,

        Impersonate::OkHttp3_9 => okhttp::okhttp3_9::get_settings,
        Impersonate::OkHttp3_11 => okhttp::okhttp3_11::get_settings,
        Impersonate::OkHttp3_13 => okhttp::okhttp3_13::get_settings,
        Impersonate::OkHttp3_14 => okhttp::okhttp3_14::get_settings,
        Impersonate::OkHttp4_9 => okhttp::okhttp4_9::get_settings,
        Impersonate::OkHttp4_10 => okhttp::okhttp4_10::get_settings,
        Impersonate::OkHttp5 => okhttp::okhttp5::get_settings,

        Impersonate::Edge99 => edge::edge99::get_settings,
        Impersonate::Edge101 => edge::edge101::get_settings,
        Impersonate::Edge122 => edge::edge122::get_settings,
        Impersonate::Edge127 => edge::edge127::get_settings
    )
}

#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Default)]
pub enum Impersonate {
    Chrome100,
    Chrome101,
    Chrome104,
    Chrome105,
    Chrome106,
    Chrome107,
    Chrome108,
    Chrome109,
    Chrome114,
    Chrome116,
    Chrome117,
    Chrome118,
    Chrome119,
    Chrome120,
    Chrome123,
    Chrome124,
    #[default]
    Chrome126,
    Chrome127,
    SafariIos17_2,
    SafariIos17_4_1,
    SafariIos16_5,
    Safari15_3,
    Safari15_5,
    Safari15_6_1,
    Safari16,
    Safari16_5,
    Safari17_0,
    Safari17_2_1,
    Safari17_4_1,
    Safari17_5,
    OkHttp3_9,
    OkHttp3_11,
    OkHttp3_13,
    OkHttp3_14,
    OkHttp4_9,
    OkHttp4_10,
    OkHttp5,
    Edge99,
    Edge101,
    Edge122,
    Edge127,
}

/// Impersonate version from string
impl FromStr for Impersonate {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chrome_100" => Ok(Impersonate::Chrome100),
            "chrome_101" => Ok(Impersonate::Chrome101),
            "chrome_104" => Ok(Impersonate::Chrome104),
            "chrome_105" => Ok(Impersonate::Chrome105),
            "chrome_106" => Ok(Impersonate::Chrome106),
            "chrome_107" => Ok(Impersonate::Chrome107),
            "chrome_108" => Ok(Impersonate::Chrome108),
            "chrome_109" => Ok(Impersonate::Chrome109),
            "chrome_114" => Ok(Impersonate::Chrome114),
            "chrome_116" => Ok(Impersonate::Chrome116),
            "chrome_117" => Ok(Impersonate::Chrome117),
            "chrome_118" => Ok(Impersonate::Chrome118),
            "chrome_119" => Ok(Impersonate::Chrome119),
            "chrome_120" => Ok(Impersonate::Chrome120),
            "chrome_123" => Ok(Impersonate::Chrome123),
            "chrome_124" => Ok(Impersonate::Chrome124),
            "chrome_126" => Ok(Impersonate::Chrome126),
            "chrome_127" => Ok(Impersonate::Chrome127),

            "safari_ios_17.2" => Ok(Impersonate::SafariIos17_2),
            "safari_ios_17.4.1" => Ok(Impersonate::SafariIos17_4_1),
            "safari_15.3" => Ok(Impersonate::Safari15_3),
            "safari_15.5" => Ok(Impersonate::Safari15_5),
            "safari_15.6.1" => Ok(Impersonate::Safari15_6_1),
            "safari_16" => Ok(Impersonate::Safari16),
            "safari_16.5" => Ok(Impersonate::Safari16_5),
            "safari_ios_16.5" => Ok(Impersonate::SafariIos16_5),
            "safari_17.0" => Ok(Impersonate::Safari17_0),
            "safari_17.2.1" => Ok(Impersonate::Safari17_2_1),
            "safari_17.4.1" => Ok(Impersonate::Safari17_4_1),
            "safari_17.5" => Ok(Impersonate::Safari17_5),

            "okhttp_3.9" => Ok(Impersonate::OkHttp3_9),
            "okhttp_3.11" => Ok(Impersonate::OkHttp3_11),
            "okhttp_3.13" => Ok(Impersonate::OkHttp3_13),
            "okhttp_3.14" => Ok(Impersonate::OkHttp3_14),
            "okhttp_4.9" => Ok(Impersonate::OkHttp4_9),
            "okhttp_4.10" => Ok(Impersonate::OkHttp4_10),
            "okhttp_5" => Ok(Impersonate::OkHttp5),

            "edge_99" => Ok(Impersonate::Edge99),
            "edge_101" => Ok(Impersonate::Edge101),
            "edge_122" => Ok(Impersonate::Edge122),
            "edge_127" => Ok(Impersonate::Edge127),
            _ => Err("Invalid impersonate version"),
        }
    }
}

impl Impersonate {
    /// Get the client profile for the given impersonate version
    pub fn profile(&self) -> ClientProfile {
        match self {
            Impersonate::Chrome100
            | Impersonate::Chrome101
            | Impersonate::Chrome104
            | Impersonate::Chrome105
            | Impersonate::Chrome106
            | Impersonate::Chrome107
            | Impersonate::Chrome108
            | Impersonate::Chrome109
            | Impersonate::Chrome114
            | Impersonate::Chrome116
            | Impersonate::Chrome117
            | Impersonate::Chrome118
            | Impersonate::Chrome119
            | Impersonate::Chrome120
            | Impersonate::Chrome123
            | Impersonate::Chrome124
            | Impersonate::Chrome126
            | Impersonate::Chrome127 => ClientProfile::Chrome,

            Impersonate::SafariIos17_2
            | Impersonate::SafariIos16_5
            | Impersonate::SafariIos17_4_1
            | Impersonate::Safari15_3
            | Impersonate::Safari15_5
            | Impersonate::Safari15_6_1
            | Impersonate::Safari16
            | Impersonate::Safari16_5
            | Impersonate::Safari17_0
            | Impersonate::Safari17_2_1
            | Impersonate::Safari17_4_1
            | Impersonate::Safari17_5 => ClientProfile::Safari,

            Impersonate::OkHttp3_9
            | Impersonate::OkHttp3_11
            | Impersonate::OkHttp3_13
            | Impersonate::OkHttp3_14
            | Impersonate::OkHttp4_9
            | Impersonate::OkHttp4_10
            | Impersonate::OkHttp5 => ClientProfile::OkHttp,

            Impersonate::Edge99
            | Impersonate::Edge101
            | Impersonate::Edge122
            | Impersonate::Edge127 => ClientProfile::Edge,
        }
    }
}

/// Client profile to impersonate
#[derive(Debug, Clone, Copy)]
pub enum ClientProfile {
    /// Chrome impersonate client profile
    Chrome,
    /// OkHttp impersonate client profile
    OkHttp,
    /// Safari impersonate client profile
    Safari,
    /// Foxfire impersonate client profile
    Firefox,
    /// Edge impersonate client profile
    Edge,
}

impl From<ClientProfile> for AgentProfile {
    fn from(val: ClientProfile) -> Self {
        match val {
            ClientProfile::Chrome => AgentProfile::Chrome,
            ClientProfile::OkHttp => AgentProfile::OkHttp,
            ClientProfile::Safari => AgentProfile::Safari,
            ClientProfile::Firefox => AgentProfile::Firefox,
            ClientProfile::Edge => AgentProfile::Edge,
        }
    }
}

/// Connection settings
pub struct ConnectSettings {
    pub tls_builder: Arc<super::Builder>,
    pub http2: Http2Settings,
}

impl Debug for ConnectSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectSettings")
            .field("tls_builder", &self.tls_builder.type_id())
            .field("http2", &self.http2)
            .finish()
    }
}

/// HTTP/2 settings.
#[derive(Debug)]
pub struct Http2Settings {
    pub initial_stream_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub max_concurrent_streams: Option<u32>,
    pub max_header_list_size: Option<u32>,
    pub header_table_size: Option<u32>,
    pub enable_push: Option<bool>,
}
