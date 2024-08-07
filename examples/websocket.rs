use futures_util::{SinkExt, StreamExt, TryStreamExt};
use rquest::{tls::Impersonate, Client, Message};
use std::error::Error;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let websocket = Client::ws_builder()
        .impersonate(Impersonate::Chrome120)
        .build()?
        .get("wss://echo.websocket.org")
        .upgrade()
        .send()
        .await?
        .into_websocket()
        .await?;

    // Or
    // let websocket = rquest::websocket("wss://echo.websocket.org").await?;

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
