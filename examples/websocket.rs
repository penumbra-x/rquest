use reqwest_impersonate as reqwest;
use std::error::Error;
use tungstenite::Message;

use futures_util::{SinkExt, StreamExt, TryStreamExt};
use reqwest::{impersonate::Impersonate, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let websocket = Client::builder()
        .impersonate_websocket(Impersonate::Chrome100)
        .build()?
        .get("wss://chatgpt-async-webps-prod-southcentralus-25.webpubsub.azure.com/client/hubs/conversations?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2NoYXRncHQtYXN5bmMtd2VicHMtcHJvZC1zb3V0aGNlbnRyYWx1cy0yNS53ZWJwdWJzdWIuYXp1cmUuY29tL2NsaWVudC9odWJzL2NvbnZlcnNhdGlvbnMiLCJpYXQiOjE3MDkwMjE5NzEsImV4cCI6MTcwOTAyNTU3MSwic3ViIjoidXNlci02NkdLTzh0MFY4TDJyMUtQODhnNXVjc00ifQ.zIu4tz5JFnnV_7IS-LKApTk3pW_RqCbLrElmqEptghY")
        .upgrade()
        .send()
        .await?
        .into_websocket()
        .await?;

    let (mut tx, mut rx) = websocket.split();

    tokio::spawn(async move {
        for i in 1..11 {
            tx.send(Message::Text(format!("Hello, World! #{i}")))
                .await
                .unwrap();
        }
    });

    while let Some(message) = rx.try_next().await? {
        match message {
            Message::Text(text) => println!("received: {text}"),
            _ => {}
        }
    }

    Ok(())
}
