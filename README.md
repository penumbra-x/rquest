# rquest

[![CI](https://github.com/0x676e67/rquest/workflows/CI/badge.svg)](https://github.com/0x676e67/rquest/actions?query=workflow%3ACI)
[![Apache-2.0](https://img.shields.io/github/license/0x676e67/rquest?color=blue)](./LICENSE)
[![Documentation](https://docs.rs/rquest/badge.svg)](https://docs.rs/rquest)
[![crates.io](https://img.shields.io/crates/v/rquest.svg)](https://crates.io/crates/rquest)
![Crates.io Total Downloads](https://img.shields.io/crates/d/rquest)

An fast asynchronous Rust `Http`/`WebSocket` Client with `TLS`/`JA3`/`JA4`/`HTTP2` fingerprint impersonate

- `Async` or `blocking` Clients
- `Plain`, `JSON`, `urlencoded`, `multipart` bodies
- Headers Order
- Customizable redirect policy
- Cookie Store
- `HTTP`/`HTTPS`/`SOCKS5` Proxies
- `HTTPS`/`WebSocket` via BoringSSL
- Preconfigured `TLS`/`HTTP2` settings
- `Chrome`/`Safari`/`Edge`/`OkHttp` Fingerprint

Additional learning resources include:

- [API Documentation](https://docs.rs/rquest)
- [Repository Examples](https://github.com/0x676e67/rquest/tree/master/examples)

## Usage

This asynchronous example uses [Tokio](https://tokio.rs) and enables some
optional features, so your `Cargo.toml` could look like this:

- HTTP

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = "0.20"
```

```rust,no_run
use std::error::Error;
use rquest::tls::Impersonate;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Build a client to mimic Edge127
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Edge127)
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

- WebSocket

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = { version = "0.20", features = ["websocket"] }
```

```rust,no_run
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use rquest::{tls::Impersonate, Client, Message};
use std::error::Error;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let websocket = rquest::websocket("wss://echo.websocket.org").await?;

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

## Requirement

Install the environment required to build [BoringSSL](https://github.com/google/boringssl/blob/master/BUILDING.md)

Do not compile with crates that depend on OpenSSL; their prefixing symbols are the same and may cause linking [failures](https://github.com/rustls/rustls/issues/2010).

## Contributing

If you would like to submit your contribution, please open a [Pull Request](https://github.com/0x676e67/rquest/pulls).

## Getting help

Your question might already be answered on the [issues](https://github.com/0x676e67/rquest/issues)

## License

Apache-2.0 [LICENSE](LICENSE)

## Accolades

The project is based on a fork of [reqwest](https://github.com/seanmonstar/reqwest).
