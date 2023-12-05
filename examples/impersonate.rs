use reqwest_impersonate as reqwest;

fn main() {
    // Build a client to mimic OkHttpAndroid13
    let client = reqwest::blocking::Client::builder()
        .impersonate(reqwest::impersonate::Impersonate::Safari15_5)
        .enable_ech_grease(true)
        .permute_extensions(true)
        .cookie_store(true)
        .tls_info(true)
        .build()
        .unwrap();

    // Use the API you're already familiar with
    // https://chat.openai.com/backend-api/models
    for _ in 0..=100 {
        match client
            .get("https://chat.openai.com/backend-api/models")
            .send()
        {
            Ok(res) => {
                println!("{}", res.text().unwrap());
            }
            Err(err) => {
                dbg!(err);
            }
        };
    }
}
