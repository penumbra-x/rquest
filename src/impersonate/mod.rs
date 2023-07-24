//! Holds structs and information to aid in impersonating a set of browsers

use std::sync::Arc;

use boring::ssl::SslConnectorBuilder;
use http::HeaderMap;

#[cfg(feature = "__impersonate")]
pub use profile::Impersonate;

#[cfg(feature = "__impersonate")]
pub mod profile;

use crate::impersonate::profile::ClientProfile;
#[cfg(feature = "__impersonate")]
pub(crate) use profile::configure_impersonate;

struct ImpersonateSettings {
    pub tls_builder_func: Arc<dyn Fn() -> SslConnectorBuilder + Send + Sync>,
    pub http2: Http2Data,
    pub headers: HeaderMap,
    pub gzip: bool,
    pub brotli: bool,
    pub client_profile: ClientProfile,
}

struct Http2Data {
    pub initial_stream_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub max_concurrent_streams: Option<u32>,
    pub max_header_list_size: Option<u32>,
    pub header_table_size: Option<u32>,
    pub enable_push: Option<bool>,
}
