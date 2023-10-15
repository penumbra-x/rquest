use reqwest_impersonate as reqwest;

fn main() {
    // Build a client to mimic OkHttpAndroid13
    let client = reqwest::blocking::Client::builder()
        .impersonate(reqwest::impersonate::Impersonate::OkHttpAndroid13)
        .cookie_store(true)
        .tls_info(true)
        .build()
        .unwrap();

    // Use the API you're already familiar with
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
