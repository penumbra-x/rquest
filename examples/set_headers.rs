use http::{header, HeaderValue};
use rquest::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome131
    let mut client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    // Set a header
    {
        client
            .headers_mut()
            .insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        let resp = client.get("https://tls.peet.ws/api/all").send().await?;
        println!("{}", resp.text().await?);
    }

    Ok(())
}
