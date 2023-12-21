# reqwest

A fork of reqwest used to impersonate the Chrome browser / OkHttp. Inspired by [curl-impersonate](https://github.com/lwthiker/curl-impersonate).

This crate was intended to be an experiment to learn more about TLS and HTTP2 fingerprinting. Some parts of reqwest may not have the code needed to work when used to copy Chrome.

It is currently missing HTTP/2 `PRIORITY` support. (PRs to [h2](https://github.com/hyperium/h2) are welcome)

These patches were made specifically for `reqwest` to work, but I would appreciate if someone took the time to PR more "proper" versions to the parent projects.

## Example

`Cargo.toml`

```toml
reqwest = { package = "reqwest-impersonate", version = "0.11.43", default-features = false, features = [
    "boring-tls",
    "impersonate",
    "blocking",
] }
```

`main.rs`

```rs
use reqwest_impersonate as reqwest;

fn main() {
    // Build a client to mimic OkHttpAndroid13
    let client = reqwest::blocking::Client::builder()
        .impersonate(reqwest::impersonate::Impersonate::Chrome120)
        .enable_ech_grease(true)
        .permute_extensions(true)
        .cookie_store(true)
        .tls_info(true)
        .build()
        .unwrap();

    // Use the API you're already familiar with
    // https://tls.peet.ws/api/all
    // https://chat.openai.com/backend-api/models
    // https://chat.openai.com/backend-api/conversation
    // https://order.surfshark.com/api/v1/account/users?source=surfshark
    match client.get("https://tls.peet.ws/api/all").send() {
        Ok(res) => {
            println!("{}", res.text().unwrap());
        }
        Err(err) => {
            dbg!(err);
        }
    };

    match client
        .post("https://chat.openai.com/backend-api/conversation")
        .send()
    {
        Ok(res) => {
            println!("{}", res.text().unwrap());
        }
        Err(err) => {
            dbg!(err);
        }
    };

}

```

## Original readme

[![crates.io](https://img.shields.io/crates/v/reqwest-impersonate.svg)](https://crates.io/crates/reqwest-impersonate)
[![Documentation](https://docs.rs/reqwest-impersonate/badge.svg)](https://docs.rs/reqwest-impersonate)
[![MIT/Apache-2 licensed](https://img.shields.io/crates/l/reqwest.svg)](./LICENSE-APACHE)
[![CI](https://github.com/seanmonstar/reqwest/workflows/CI/badge.svg)](https://github.com/seanmonstar/reqwest/actions?query=workflow%3ACI)

An ergonomic, batteries-included HTTP Client for Rust.

- Plain bodies, JSON, urlencoded, multipart
- Customizable redirect policy
- HTTP Proxies
- HTTPS via system-native TLS (or optionally, rustls)
- Cookie Store
- WASM
- [Changelog](CHANGELOG.md)

## Example

This asynchronous example uses [Tokio](https://tokio.rs) and enables some
optional features, so your `Cargo.toml` could look like this:

```toml
[dependencies]
reqwest = { version = "0.11", features = ["json"] }
tokio = { version = "1", features = ["full"] }
```

And then the code:

```rust,no_run
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resp = reqwest::get("https://httpbin.org/ip")
        .await?
        .json::<HashMap<String, String>>()
        .await?;
    println!("{:#?}", resp);
    Ok(())
}
```

## Blocking Client

There is an optional "blocking" client API that can be enabled:

```toml
[dependencies]
reqwest = { version = "0.11", features = ["blocking", "json"] }
```

```rust,no_run
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resp = reqwest::blocking::get("https://httpbin.org/ip")?
        .json::<HashMap<String, String>>()?;
    println!("{:#?}", resp);
    Ok(())
}
```

## Requirements

On Linux:

- OpenSSL 1.0.1, 1.0.2, 1.1.0, or 1.1.1 with headers (see <https://github.com/sfackler/rust-openssl>)

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
