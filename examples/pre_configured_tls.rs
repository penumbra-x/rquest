use std::error::Error;

use boring::ssl::{SslConnector, SslMethod};
use http::HeaderValue;
use rquest::{
    tls::{Http2FrameSettings, TlsExtensionSettings, TlsSettings, Version},
    HttpVersionPref,
};
use rquest::{PseudoOrder, SettingsOrder, StreamDependency, StreamId};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let settings = TlsSettings {
        builder: SslConnector::builder(SslMethod::tls_client())?,
        extension: TlsExtensionSettings {
            tls_sni: true,
            http_version_pref: HttpVersionPref::Http2,
            min_tls_version: Some(Version::TLS_1_0),
            max_tls_version: Some(Version::TLS_1_3),
            application_settings: true,
            pre_shared_key: true,
            enable_ech_grease: true,
            permute_extensions: true,
        },
        http2: Http2FrameSettings {
            initial_stream_window_size: Some(6291456),
            initial_connection_window_size: Some(15728640),
            max_concurrent_streams: Some(1000),
            max_header_list_size: Some(262144),
            header_table_size: Some(65536),
            enable_push: None,
            headers_priority: Some(StreamDependency::new(StreamId::zero(), 255, true)),
            headers_pseudo_order: Some([
                PseudoOrder::Method,
                PseudoOrder::Scheme,
                PseudoOrder::Authority,
                PseudoOrder::Path,
            ]),
            settings_order: Some([
                SettingsOrder::InitialWindowSize,
                SettingsOrder::MaxConcurrentStreams,
            ]),
        },
    };

    // Build a client with pre-configured TLS settings
    let client = rquest::Client::builder()
        .use_preconfigured_tls(settings, |headers| {
            headers.insert("user-agent", HeaderValue::from_static("rquest"));
        })
        .enable_ech_grease()
        .permute_extensions()
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
