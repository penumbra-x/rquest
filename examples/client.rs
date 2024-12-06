use http::{header, HeaderName, HeaderValue};
use rquest::{tls::Impersonate, Client};
use std::net::Ipv4Addr;

static HEADER_ORDER: [HeaderName; 6] = [
    header::ACCEPT_LANGUAGE,
    header::USER_AGENT,
    header::ACCEPT_ENCODING,
    header::HOST,
    header::COOKIE,
    HeaderName::from_static("priority"),
];

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome131
    let mut client = Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;

    // Set the headers order
    client.set_headers_order(&HEADER_ORDER);

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    // Change the impersonate to Safari18
    client.set_impersonate(Impersonate::Safari18)?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    // Change the impersonate to Chrome131 without setting the headers
    client.set_impersonate_without_headers(Impersonate::Edge127)?;

    // Set a header
    client
        .headers_mut()
        .insert(header::ACCEPT, "application/json".parse().unwrap());

    // Set a cookie
    client.set_cookies(
        vec![HeaderValue::from_static("foo=bar; Domain=tls.peet.ws")],
        "https://tls.peet.ws/api/all",
    )?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    // Set the local address
    client.set_local_address(Some(Ipv4Addr::new(172, 20, 10, 2).into()));

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    // Set the interface
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    {
        client.set_interface("eth0");

        let resp = client.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);
    }

    // ⚠️ Please note that `set_impersonate`, `set_impersonate_without_headers` will reset all settings, including proxy, header information, etc.,
    // When using Client's `set_headers_order`, `headers_mut`, `set_impersonate`, `set_impersonate_without_headers`,
    // `set_interface`, `set_local_address`, `set_local_addresss`, `set_proxies` methods,
    // When the reference count of the Client is 1, the current Client's settings will be changed, otherwise a new Client will be created and will not affect the previous Client, but will share the same connection pool
    let mut client2 = client.clone();

    // Set the impersonate to Chrome131
    // Expected: Chrome131
    {
        client2.set_impersonate(Impersonate::Chrome131)?;

        let resp = client2.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);
    }

    // But not change the original client
    // Expected: Edge127
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
