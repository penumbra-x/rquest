# rquest

[![crates.io](https://img.shields.io/crates/v/rquest.svg)](https://crates.io/crates/rquest)
[![MIT/Apache-2 licensed](https://img.shields.io/crates/l/rquest.svg)](./LICENSE-APACHE)
[![CI](https://github.com/0x676e67/rquest/workflows/CI/badge.svg)](https://github.com/0x676e67/rquest/actions?query=workflow%3ACI)

An intuitive and robust Rust `HTTP`/`WebSocket` Client featuring TLS/JA3/JA4/HTTP2 fingerprint impersonate

- Impersonate Chrome / Safari / Edge / OkHttp
- Plain bodies, JSON, urlencoded, multipart
- Customizable redirect policy
- `HTTP`/`HTTPS`/`Socks5` Proxies
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
use rquest;
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
use rquest;
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

- MIT license ([LICENSE](LICENSE) or <http://opensource.org/licenses/MIT>)

## Sponsors

[![Capsolver](https://github.com/0x676e67/CapSolver-CloudflareBypass/raw/main/docs/capsolver.jpeg)](https://dashboard.capsolver.com/passport/register?inviteCode=y7CtB_a-3X6d)
[Capsolver.com](https://www.capsolver.com/?utm_source=github&utm_medium=banner_github&utm_campaign=fcsrv) is an AI-powered service that specializes in solving various types of captchas automatically. It supports captchas such as [reCAPTCHA V2](https://docs.capsolver.com/guide/captcha/ReCaptchaV2.html?utm_source=github&utm_medium=banner_github&utm_campaign=fcsrv), [reCAPTCHA V3](https://docs.capsolver.com/guide/captcha/ReCaptchaV3.html?utm_source=github&utm_medium=banner_github&utm_campaign=fcsrv), [hCaptcha](https://docs.capsolver.com/guide/captcha/HCaptcha.html?utm_source=github&utm_medium=banner_github&utm_campaign=fcsrv), [FunCaptcha](https://docs.capsolver.com/guide/captcha/FunCaptcha.html?utm_source=github&utm_medium=banner_github&utm_campaign=fcsrv), [DataDome](https://docs.capsolver.com/guide/captcha/DataDome.html?utm_source=github&utm_medium=banner_github&utm_campaign=fcsrv), [AWS Captcha](https://docs.capsolver.com/guide/captcha/awsWaf.html?utm_source=github&utm_medium=banner_github&utm_campaign=fcsrv), [Geetest](https://docs.capsolver.com/guide/captcha/Geetest.html?utm_source=github&utm_medium=banner_github&utm_campaign=fcsrv), and Cloudflare [Captcha](https://docs.capsolver.com/guide/antibots/cloudflare_turnstile.html?utm_source=github&utm_medium=banner_github&utm_campaign=fcsrv) / [Challenge 5s](https://docs.capsolver.com/guide/antibots/cloudflare_challenge.html?utm_source=github&utm_medium=banner_github&utm_campaign=fcsrv), [Imperva / Incapsula](https://docs.capsolver.com/guide/antibots/imperva.html?utm_source=github&utm_medium=banner_github&utm_campaign=fcsrv), among others.
For developers, Capsolver offers API integration options detailed in their [documentation](https://docs.capsolver.com/?utm_source=github&utm_medium=banner_github&utm_campaign=fcsrv), facilitating the integration of captcha solving into applications. They also provide browser extensions for [Chrome](https://chromewebstore.google.com/detail/captcha-solver-auto-captc/pgojnojmmhpofjgdmaebadhbocahppod) and [Firefox](https://addons.mozilla.org/es/firefox/addon/capsolver-captcha-solver/), making it easy to use their service directly within a browser. Different pricing packages are available to accommodate varying needs, ensuring flexibility for users.
