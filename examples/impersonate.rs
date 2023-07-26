fn main() {
    // Build a client to mimic Chrome 110
    let client = reqwest::blocking::Client::builder()
        .impersonate_builder(reqwest::impersonate::Impersonate::OkHttpAndroid13)
        .build()
        .unwrap();

    // Use the API you're already familiar with
    match client.get("https://chat.openai.com/backend-api/models").send() {
        Ok(res) => {
            println!("{}", res.text().unwrap());
        }
        Err(err) => {
            dbg!(err);
        }
    };
}