use reqwest::impersonate::Impersonate;
use reqwest_impersonate as reqwest;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Build a client to mimic Chrome123
    let client = reqwest::Client::builder()
        .impersonate(Impersonate::Chrome123)
        .enable_ech_grease(true)
        .permute_extensions(true)
        .cookie_store(true)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
