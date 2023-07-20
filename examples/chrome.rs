use reqwest::browser::ChromeVersion;

fn main() {
    // Build a client to mimic Chrome v99
    let client = reqwest::blocking::Client::builder()
        .chrome_builder(ChromeVersion::V99Android)
        .build()
        .unwrap();

    // Use the API you're already familiar with
    match client.get("https://chat.openai.com/backend-api/models").send() {
        Ok(res) => {
            println!("{:?}", res.text().unwrap());
        }
        Err(err) => {
            dbg!(err);
        }
    };
}