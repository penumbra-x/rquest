#![cfg(not(target_arch = "wasm32"))]

#[tokio::test]
async fn test_badssl_modern() {
    let text = rquest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get("https://mozilla-modern.badssl.com/")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(text.contains("<title>mozilla-modern.badssl.com</title>"));
}

#[cfg(feature = "boring-tls")]
#[tokio::test]
async fn test_badssl_self_signed() {
    let text = rquest::Client::builder()
        .impersonate(rquest::tls::Impersonate::OkHttp4_9)
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .unwrap()
        .get("https://self-signed.badssl.com/")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(text.contains("<title>self-signed.badssl.com</title>"));
}
