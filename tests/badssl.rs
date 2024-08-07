#![cfg(not(target_arch = "wasm32"))]

#[cfg(all(feature = "__tls"))]
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

#[cfg(feature = "__tls")]
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

#[cfg(feature = "__tls")]
#[tokio::test]
async fn test_badssl_no_built_in_roots() {
    let result = rquest::Client::builder()
        .tls_built_in_root_certs(false)
        .no_proxy()
        .build()
        .unwrap()
        .get("https://untrusted-root.badssl.com/")
        .send()
        .await;

    assert!(result.is_err());
}
