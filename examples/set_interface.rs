use rquest::tls::Impersonate;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a client to mimic Chrome126
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome126)
        .enable_ech_grease()
        .interface("eth0")
        .permute_extensions()
        .build()?;

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome126)
        .enable_ech_grease()
        .permute_extensions()
        .build()?;

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
