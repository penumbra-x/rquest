use reqwest_impersonate as reqwest;
use std::error::Error;
use tungstenite::Message;

use futures_util::{SinkExt, StreamExt, TryStreamExt};
use reqwest::{impersonate::Impersonate, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let upgrade_response = Client::builder()
        .impersonate_websocket(Impersonate::Chrome120)
        .build()?
        .get("ws://localhost:7999/ws/wss://chatgpt-async-webps-prod-centralus-0.chatgpt.com/client/hubs/conversations?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2NoYXRncHQtYXN5bmMtd2VicHMtcHJvZC1jZW50cmFsdXMtMC53ZWJwdWJzdWIuYXp1cmUuY29tL2NsaWVudC9odWJzL2NvbnZlcnNhdGlvbnMiLCJpYXQiOjE3MTQ1Mzc2NzUsImV4cCI6MTcxNDU0MTI3NSwic3ViIjoidXNlci1wVmpneXdhekpTcm5WUnZ6clhtem90Z1AiLCJyb2xlIjpbIndlYnB1YnN1Yi5qb2luTGVhdmVHcm91cC51c2VyLXBWamd5d2F6SlNyblZSdnpyWG16b3RnUCJdLCJ3ZWJwdWJzdWIuZ3JvdXAiOlsidXNlci1wVmpneXdhekpTcm5WUnZ6clhtem90Z1AiXX0.36VYXmJysuC9btGPAa7fejaE2pWWIiFDeAObtxro-vc")
        .upgrade()
        .protocols(vec!["json.reliable.webpubsub.azure.v1".to_owned()])
        .header("sec-websocket-key", "IbcH9nyQreI4tM2z9nnPDw==")
        .send()
        .await?;

    println!("{:?}", upgrade_response.status());
    println!("{:?}", upgrade_response.headers());

    let websocket = upgrade_response.into_websocket().await?;

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
