use super::CIPHER_LIST;
use crate::tls::builder::{SafariTlsBuilder, TlsBuilder};
use crate::tls::{Http2FrameSettings, TlsSettings};
use crate::tls::{ImpersonateSettings, TlsResult};
use http::{
    header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT},
    HeaderMap, HeaderValue,
};

pub(crate) fn get_settings(
    settings: ImpersonateSettings,
) -> TlsResult<(TlsSettings, impl FnOnce(&mut HeaderMap))> {
    Ok((
        TlsSettings {
            builder: SafariTlsBuilder::new(&CIPHER_LIST)?,
            extension: settings.extension,
            http2: Http2FrameSettings {
                initial_stream_window_size: Some(4194304),
                initial_connection_window_size: Some(10551295),
                max_concurrent_streams: Some(100),
                max_header_list_size: None,
                header_table_size: None,
                enable_push: None,
                headers_priority: settings.headers_priority,
                headers_pseudo_order: settings.headers_pseudo_order,
                settings_order: settings.settings_order,
            },
        },
        header_initializer,
    ))
}

fn header_initializer(headers: &mut HeaderMap) {
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15"));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
}
