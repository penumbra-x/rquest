use std::net::Ipv4Addr;

use reqwest::impersonate::Impersonate;
use reqwest_impersonate as reqwest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a client to mimic Chrome126
    let mut client = reqwest::Client::builder()
        .impersonate(Impersonate::Chrome126)
        .enable_ech_grease()
        .permute_extensions()
        .build()?;

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    // let proxy = reqwest::Proxy::all("socks5h://127.0.0.1:1080")?;
    client.set_local_address(Some(Ipv4Addr::new(172, 20, 10, 2).into()));

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
