#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, deny(warnings))]

//! # rquest
//!
//! The `rquest` crate provides a convenient, higher-level HTTP
//! [`Client`][client].
//!
//! It handles many of the things that most people just expect an HTTP client
//! to do for them.
//!
//! In addition, it also provides common browser TLS/Http2 fingerprint simulation.
//!
//! - [Impersonate](#impersonate) Chrome / Safari / Edge / OkHttp
//! - Async and [blocking] Clients
//! - Plain bodies, [JSON](#json), [urlencoded](#forms), [multipart], [websocket](#websocket)
//! - Customizable [redirect policy](#redirect-policies)
//! - HTTP [Proxies](#proxies)
//! - Uses BoringSSL [TLS](#tls)
//! - Cookies
//!
//! Additional learning resources include:
//!
//! - [The Rust Cookbook](https://rust-lang-nursery.github.io/rust-cookbook/web/clients.html)
//! - [Repository Examples](https://github.com/0x676e67/rquest/tree/master/examples)
//!
//! ## Making a GET request
//!
//! For a single request, you can use the [`get`][get] shortcut method.
//!
//! ```rust
//! # async fn run() -> Result<(), rquest::Error> {
//! let body = rquest::get("https://www.rust-lang.org")
//!     .await?
//!     .text()
//!     .await?;
//!
//! println!("body = {:?}", body);
//! # Ok(())
//! # }
//! ```
//!
//! **NOTE**: If you plan to perform multiple requests, it is best to create a
//! [`Client`][client] and reuse it, taking advantage of keep-alive connection
//! pooling.
//!
//! ## Making POST requests (or setting request bodies)
//!
//! There are several ways you can set the body of a request. The basic one is
//! by using the `body()` method of a [`RequestBuilder`][builder]. This lets you set the
//! exact raw bytes of what the body should be. It accepts various types,
//! including `String` and `Vec<u8>`. If you wish to pass a custom
//! type, you can use the `rquest::Body` constructors.
//!
//! ```rust
//! # use rquest::Error;
//! #
//! # async fn run() -> Result<(), Error> {
//! let client = rquest::Client::new();
//! let res = client.post("http://httpbin.org/post")
//!     .body("the exact body that is sent")
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Forms
//!
//! It's very common to want to send form data in a request body. This can be
//! done with any type that can be serialized into form data.
//!
//! This can be an array of tuples, or a `HashMap`, or a custom type that
//! implements [`Serialize`][serde].
//!
//! ```rust
//! # use rquest::Error;
//! #
//! # async fn run() -> Result<(), Error> {
//! // This will POST a body of `foo=bar&baz=quux`
//! let params = [("foo", "bar"), ("baz", "quux")];
//! let client = rquest::Client::new();
//! let res = client.post("http://httpbin.org/post")
//!     .form(&params)
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### JSON
//!
//! There is also a `json` method helper on the [`RequestBuilder`][builder] that works in
//! a similar fashion the `form` method. It can take any value that can be
//! serialized into JSON. The feature `json` is required.
//!
//! ```rust
//! # use rquest::Error;
//! # use std::collections::HashMap;
//! #
//! # #[cfg(feature = "json")]
//! # async fn run() -> Result<(), Error> {
//! // This will POST a body of `{"lang":"rust","body":"json"}`
//! let mut map = HashMap::new();
//! map.insert("lang", "rust");
//! map.insert("body", "json");
//!
//! let client = rquest::Client::new();
//! let res = client.post("http://httpbin.org/post")
//!     .json(&map)
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Impersonate
//!
//! The `impersonate` module provides a way to simulate various browser fingerprints.
//!
//! ```rust,no_run
//! use std::error::Error;
//! use rquest::impersonate::Impersonate;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn Error>> {
//!     // Build a client to mimic Chrome123
//!     let client = rquest::Client::builder()
//!         .impersonate(Impersonate::Chrome123)
//!         .enable_ech_grease()
//!         .permute_extensions()
//!         .cookie_store(true)
//!         .build()?;
//!
//!     // Use the API you're already familiar with
//!     let resp = client.get("https://tls.peet.ws/api/all").send().await?;
//!     println!("{}", resp.text().await?);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Websocket
//!
//! The `websocket` module provides a way to upgrade a connection to a websocket.
//!
//! ```rust,no_run
//! use std::error::Error;
//! use tungstenite::Message;
//!
//! use futures_util::{SinkExt, StreamExt, TryStreamExt};
//! use rquest::{impersonate::Impersonate, Client};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn Error>> {
//!     let websocket = Client::builder()
//!         .impersonate_websocket(Impersonate::Chrome120)
//!         .build()?
//!         .get("wss://echo.websocket.org")
//!         .upgrade()
//!         .send()
//!         .await?
//!         .into_websocket()
//!         .await?;
//!
//!     let (mut tx, mut rx) = websocket.split();
//!
//!     tokio::spawn(async move {
//!         for i in 1..11 {
//!             tx.send(Message::Text(format!("Hello, World! #{i}")))
//!                 .await
//!                 .unwrap();
//!         }
//!     });
//!
//!     while let Some(message) = rx.try_next().await? {
//!         match message {
//!             Message::Text(text) => println!("received: {text}"),
//!             _ => {}
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Redirect Policies
//!
//! By default, a `Client` will automatically handle HTTP redirects, having a
//! maximum redirect chain of 10 hops. To customize this behavior, a
//! [`redirect::Policy`][redirect] can be used with a `ClientBuilder`.
//!
//! ## Cookies
//!
//! The automatic storing and sending of session cookies can be enabled with
//! the [`cookie_store`][ClientBuilder::cookie_store] method on `ClientBuilder`.
//!
//! ## Proxies
//!
//! **NOTE**: System proxies are enabled by default.
//!
//! System proxies look in environment variables to set HTTP or HTTPS proxies.
//!
//! `HTTP_PROXY` or `http_proxy` provide http proxies for http connections while
//! `HTTPS_PROXY` or `https_proxy` provide HTTPS proxies for HTTPS connections.
//!
//! These can be overwritten by adding a [`Proxy`] to `ClientBuilder`
//! i.e. `let proxy = rquest::Proxy::http("https://secure.example")?;`
//! or disabled by calling `ClientBuilder::no_proxy()`.
//!
//! `socks` feature is required if you have configured socks proxy like this:
//!
//! ```bash
//! export https_proxy=socks5://127.0.0.1:1086
//! ```
//! ## TLS
//!
//! By default, clients will utilize BoringSSL transport layer security to connect to HTTPS targets.
//!
//! - Various parts of TLS can also be configured or even disabled on the
//!   `ClientBuilder`.
//!
//! ## Optional Features
//!
//! The following are a list of [Cargo features][cargo-features] that can be
//! enabled or disabled:
//!
//! - **boring-tls** *(enabled by default)*: Provides TLS support to connect
//!   over HTTPS.
//! - **impersonate** *(enabled by default)*: Provides browser fingerprint
//! - **websocket**: Provides websocket support.
//! - **blocking**: Provides the [blocking][] client API.
//! - **cookies**: Provides cookie session support.
//! - **gzip**: Provides response body gzip decompression.
//! - **brotli**: Provides response body brotli decompression.
//! - **zstd**: Provides response body zstd decompression.
//! - **deflate**: Provides response body deflate decompression.
//! - **json**: Provides serialization and deserialization for JSON bodies.
//! - **multipart**: Provides functionality for multipart forms.
//! - **stream**: Adds support for `futures::Stream`.
//! - **socks**: Provides SOCKS5 proxy support.
//! - **hickory-dns**: Enables a hickory-dns async resolver instead of default
//!   threadpool using `getaddrinfo`.
//!
//! [hyper]: http://hyper.rs
//! [blocking]: ./blocking/index.html
//! [client]: ./struct.Client.html
//! [response]: ./struct.Response.html
//! [get]: ./fn.get.html
//! [builder]: ./struct.RequestBuilder.html
//! [serde]: http://serde.rs
//! [redirect]: crate::redirect
//! [Proxy]: ./struct.Proxy.html
//! [cargo-features]: https://doc.rust-lang.org/stable/cargo/reference/manifest.html#the-features-section

/// Re-export of boring to keep versions in check
pub use boring;
pub use boring_sys;
pub use http::header;
pub use http::Method;
pub use http::{StatusCode, Version};
pub use url::Url;

// universal mods
#[macro_use]
mod error;
/// HTTP client implementate module
pub mod impersonate;
mod into_url;
mod response;

pub use self::error::{Error, Result};
pub use self::into_url::IntoUrl;
pub use self::response::ResponseBuilderExt;

/// Shortcut method to quickly make a `GET` request.
///
/// See also the methods on the [`rquest::Response`](./struct.Response.html)
/// type.
///
/// **NOTE**: This function creates a new internal `Client` on each call,
/// and so should not be used if making many requests. Create a
/// [`Client`](./struct.Client.html) instead.
///
/// # Examples
///
/// ```rust
/// # async fn run() -> Result<(), rquest::Error> {
/// let body = rquest::get("https://www.rust-lang.org").await?
///     .text().await?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// This function fails if:
///
/// - native TLS backend cannot be initialized
/// - supplied `Url` cannot be parsed
/// - there was an error while sending request
/// - redirect limit was exhausted
pub async fn get<T: IntoUrl>(url: T) -> crate::Result<Response> {
    Client::builder().build()?.get(url).send().await
}

/// Opens a websocket at the specified URL.
///
/// This is a shorthand for creating a request, sending it, and turning the
/// response into a websocket.
#[cfg(all(feature = "websocket", not(target_arch = "wasm32")))]
pub async fn websocket<T: IntoUrl>(url: T) -> crate::Result<async_impl::websocket::WebSocket> {
    Ok(Client::new()
        .get(url)
        .upgrade()
        .send()
        .await?
        .into_websocket()
        .await?)
}

fn _assert_impls() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    fn assert_clone<T: Clone>() {}

    assert_send::<Client>();
    assert_sync::<Client>();
    assert_clone::<Client>();

    assert_send::<Request>();
    assert_send::<RequestBuilder>();

    #[cfg(not(target_arch = "wasm32"))]
    {
        assert_send::<Response>();
    }

    assert_send::<Error>();
    assert_sync::<Error>();
}

#[cfg(test)]
doc_comment::doctest!("../README.md");

#[cfg(feature = "multipart")]
pub use self::async_impl::multipart;
#[cfg(feature = "websocket")]
pub use self::async_impl::websocket::{
    Message, WebSocket, WebSocketRequestBuilder, WebSocketResponse,
};
pub use self::async_impl::{
    Body, Client, ClientBuilder, Request, RequestBuilder, Response, Upgraded,
};
pub use self::proxy::{NoProxy, Proxy};

mod async_impl;
#[cfg(feature = "blocking")]
pub mod blocking;
mod connect;
#[cfg(feature = "cookies")]
pub mod cookie;
pub mod dns;
mod proxy;
pub mod redirect;
pub mod tls;
mod util;
