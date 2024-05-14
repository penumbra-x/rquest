# reqwest-impersonate

[![crates.io](https://img.shields.io/crates/v/reqwest-impersonate.svg)](https://crates.io/crates/reqwest-impersonate)
[![MIT/Apache-2 licensed](https://img.shields.io/crates/l/reqwest.svg)](./LICENSE-APACHE)
[![CI](https://github.com/seanmonstar/reqwest/workflows/CI/badge.svg)](https://github.com/seanmonstar/reqwest/actions?query=workflow%3ACI)

An ergonomic, batteries-included HTTP Client for Rust.

- Plain bodies, JSON, urlencoded, multipart
- Customizable redirect policy
- HTTP Proxies
- HTTPS via BoringSSL
- WebSocket
- Cookie Store
- WASM
- [Changelog](CHANGELOG.md)

> A fork of reqwest used to impersonate the Chrome browser / OkHttp. Inspired by [curl-impersonate](https://github.com/lwthiker/curl-impersonate).

## Example

This asynchronous example uses [Tokio](https://tokio.rs) and enables some
optional features, so your `Cargo.toml` could look like this:

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
reqwest_impersonate = "0.11"
```

Or WebSocket:

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
reqwest_impersonate = { version = "0.11", features = ["websocket"] }
```

And then the code:

```rust,no_run
use std::error::Error;
use reqwest_impersonate as reqwest;
use reqwest::impersonate::Impersonate;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Build a client to mimic Chrome123
    let client = reqwest::Client::builder()
        .impersonate(Impersonate::Chrome123)
        .enable_ech_grease()
        .permute_extensions()
        .cookie_store(true)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
```

And then the websocket code:

```rust,no_run
use reqwest_impersonate as reqwest;
use std::error::Error;
use tungstenite::Message;

use futures_util::{SinkExt, StreamExt, TryStreamExt};
use reqwest::{impersonate::Impersonate, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let websocket = Client::builder()
        .impersonate_websocket(Impersonate::Chrome120)
        .build()?
        .get("wss://echo.websocket.org")
        .upgrade()
        .send()
        .await?
        .into_websocket()
        .await?;

    let (mut tx, mut rx) = websocket.split();

    tokio::spawn(async move {
        for i in 1..11 {
            tx.send(Message::Text(format!("Hello, World! #{i}")))
                .await
                .unwrap();
        }
    });

    while let Some(message) = rx.try_next().await? {
        match message {
            Message::Text(text) => println!("received: {text}"),
            _ => {}
        }
    }

    Ok(())
}
```

## Requirements

On Linux:

- OpenSSL with headers. See https://docs.rs/openssl for supported versions
  and more details. Alternatively you can enable the `native-tls-vendored`
  feature to compile a copy of OpenSSL.

On Windows and macOS:

- Nothing.

Reqwest uses [rust-native-tls](https://github.com/sfackler/rust-native-tls),
which will use the operating system TLS framework if available, meaning Windows
and macOS. On Linux, it will use OpenSSL 1.1.


## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
