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
        vec![HeaderValue::from_static("foo=bar; Domain=tls.peet.ws")],
        "https://tls.peet.ws/api/all",
    )?;

    // Get cookies
    let cookies = client.get_cookies("https://tls.peet.ws/api/all")?;
    println!("{:?}", cookies);

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
