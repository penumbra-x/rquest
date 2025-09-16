use http::Version;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Use the API you're already familiar with
    let resp = wreq::get("https://www.google.com")
        .version(Version::HTTP_11)
        .send()
        .await?;

    assert_eq!(resp.version(), Version::HTTP_11);
    println!("{}", resp.text().await?);

    Ok(())
}
