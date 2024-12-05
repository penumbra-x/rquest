use http::HeaderValue;
use rquest::tls::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome131
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome131)
        .cookie_store(true)
        .build()?;

    // Set a cookie
    client.set_cookies(
        vec![HeaderValue::from_str("foo=bar; Domain=tls.peet.ws").unwrap()],
        "https://tls.peet.ws/api/all",
    )?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
