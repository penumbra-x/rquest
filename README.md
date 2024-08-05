# rquest

[![crates.io](https://img.shields.io/crates/v/rquest.svg)](https://crates.io/crates/rquest)
[![MIT/Apache-2 licensed](https://img.shields.io/crates/l/rquest.svg)](./LICENSE-APACHE)
[![CI](https://github.com/0x676e67/rquest/workflows/CI/badge.svg)](https://github.com/0x676e67/rquest/actions?query=workflow%3ACI)

An intuitive and robust Rust `HTTP`/`WebSocket` Client featuring TLS/JA3/JA4/HTTP2 fingerprint impersonate

- Impersonate Chrome / Safari / Edge / OkHttp
- Plain bodies, JSON, urlencoded, multipart
- Customizable redirect policy
- `HTTP`/`HTTPS`/`Socks5`/`Socks5h` Proxies
- `HTTPS`/`WebSocket` via BoringSSL
- Cookie Store
- [Changelog](CHANGELOG.md)

## Example

This asynchronous example uses [Tokio](https://tokio.rs) and enables some
optional features, so your `Cargo.toml` could look like this:

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = "0.11"
```

Or WebSocket:

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = { version = "0.11", features = ["websocket"] }
```

And then the code:

```rust,no_run
use std::error::Error;
use rquest::impersonate::Impersonate;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Build a client to mimic Chrome123
    let client = rquest::Client::builder()
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
use std::error::Error;
use tungstenite::Message;

use futures_util::{SinkExt, StreamExt, TryStreamExt};
use rquest::{impersonate::Impersonate, Client};

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

## Contributing

If you would like to submit your contribution, please open a [Pull Request](https://github.com/0x676e67/rquest/pulls).

## Getting help

Your question might already be answered on the [issues](https://github.com/0x676e67/rquest/issues)

## License

MIT license ([LICENSE](LICENSE) or <http://opensource.org/licenses/MIT>)
