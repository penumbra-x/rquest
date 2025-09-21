# wreq

[![CI](https://github.com/0x676e67/wreq/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/wreq/actions/workflows/ci.yml)
[![Crates.io License](https://img.shields.io/crates/l/wreq)](./LICENSE)
[![Crates.io MSRV](https://img.shields.io/crates/msrv/wreq?logo=rust)](https://crates.io/crates/wreq)
[![crates.io](https://img.shields.io/crates/v/wreq.svg?logo=rust)](https://crates.io/crates/wreq)
[![docs.rs](https://img.shields.io/docsrs/wreq?color=blue&logo=rust)](https://docs.rs/wreq)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md)

An ergonomic and modular Rust HTTP client for advanced and low-level emulation, with customizable TLS, JA3/JA4, and HTTP/2 fingerprinting capabilities.

## Features

- Plain bodies, JSON, urlencoded, multipart
- Cookie Store
- Redirect Policy
- Original Header
- Rotating Proxies
- Certificate Store
- Tower Middleware
- WebSocket Upgrade
- HTTPS via BoringSSL
- HTTP/2 over TLS Emulation

## Example

The following example uses the [Tokio](https://tokio.rs) runtime with optional features enabled by adding this to your `Cargo.toml`:

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
wreq = "6.0.0-rc.20"
wreq-util = "3.0.0-rc.3"
```

And then the code:

```rust
use wreq::Client;
use wreq_util::Emulation;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Build a client
    let client = Client::builder()
        .emulation(Emulation::Safari26)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
```

## Emulation

- **HTTP/2 over TLS**

Due to the complexity of TLS encryption and the widespread adoption of HTTP/2, browser fingerprints such as **JA3**, **JA4**, and **Akamai** cannot be reliably emulated using simple fingerprint strings. Instead of parsing and emulating these string-based fingerprints, `wreq` provides fine-grained control over TLS and HTTP/2 extensions and settings for precise browser behavior emulation.

- **Device Emulation**

Most browser device models share identical TLS and HTTP/2 configurations, differing only in the `User-Agent` string. Common browser device emulation templates are maintained in [`wreq-util`](https://github.com/0x676e67/wreq-util), a companion utility crate.

## Services

Help sustain the ongoing development of this open-source project by reaching out for [commercial support](mailto:gngppz@gmail.com). Receive private guidance, expert reviews, or direct access to the maintainer, with personalized technical assistance tailored to your needs.

## Building

Avoid compiling with packages that depend on `openssl-sys`, as it shares the same prefix symbol with `boring-sys`, potentially leading to [link failures](https://github.com/cloudflare/boring/issues/197) and other issues. Even if compilation succeeds, using both `openssl-sys` and `boring-sys` together can result in memory segmentation faults. Until the upstream Boring resolves these linking conflicts, using `rustls` is the best workaround.

Install the dependencies required to build [BoringSSL](https://github.com/google/boringssl/blob/master/BUILDING.md#build-prerequisites)

```shell
sudo apt-get install build-essential cmake perl pkg-config libclang-dev musl-tools git -y

cargo build --release
```

This GitHub Actions [workflow](.github/compilation-guide/build.yml) can be used to compile the project on **Linux**, **Windows**, and **macOS**.

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE](./LICENSE) or http://www.apache.org/licenses/LICENSE-2.0).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the [Apache-2.0](./LICENSE) license, shall be licensed as above, without any additional terms or conditions.

## Accolades

A hard fork of [reqwest](https://github.com/seanmonstar/reqwest).
