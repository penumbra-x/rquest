use rquest::tls::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Firefox133
    let client = rquest::Client::builder()
        .impersonate_skip_headers(Impersonate::Firefox133)
        .with_http2_builder(|builder| builder.initial_stream_id(3))
        .with_http1_builder(|builder| builder.http09_responses(true))
        .build()?;

    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);
    Ok(())
}
