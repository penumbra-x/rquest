//! HTTP2 settings.
#![allow(missing_docs)]

use hyper2::{Priority, PseudoOrder, SettingsOrder};
use std::borrow::Cow;
use typed_builder::TypedBuilder;

/// HTTP2 settings.
#[derive(TypedBuilder, Debug)]
pub struct Http2Settings {
    #[builder(default, setter(into))]
    pub initial_stream_id: Option<u32>,

    // ============== windows update frame ==============
    #[builder(default, setter(into))]
    pub initial_connection_window_size: Option<u32>,

    // ============== settings frame ==============
    #[builder(default, setter(into))]
    pub header_table_size: Option<u32>,

    #[builder(default, setter(into))]
    pub enable_push: Option<bool>,

    #[builder(default, setter(into))]
    pub max_concurrent_streams: Option<u32>,

    #[builder(default, setter(into))]
    pub initial_stream_window_size: Option<u32>,

    #[builder(default, setter(into))]
    pub max_frame_size: Option<u32>,

    #[builder(default, setter(into))]
    pub max_header_list_size: Option<u32>,

    #[builder(default, setter(into))]
    pub unknown_setting8: Option<bool>,

    #[builder(default, setter(into))]
    pub unknown_setting9: Option<bool>,

    #[builder(default, setter(strip_option))]
    pub settings_order: Option<[SettingsOrder; 8]>,

    // ============== headers frame ==============
    #[builder(default, setter(into))]
    pub headers_priority: Option<(u32, u8, bool)>,

    #[builder(default, setter(into))]
    pub headers_pseudo_order: Option<[PseudoOrder; 4]>,

    // ============== priority ==============
    #[builder(default, setter(into))]
    pub priority: Option<Cow<'static, [Priority]>>,
}
