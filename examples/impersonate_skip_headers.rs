use rquest::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome130 with headers
    let client = rquest::Client::builder()
        .impersonate_skip_headers(Impersonate::Chrome130)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
