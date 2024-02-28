use std::{
    pin::Pin, task::{
        Context,
        Poll,
    }
};

use futures_util::{
    Sink,
    SinkExt,
    Stream,
    StreamExt,
};
use http::{header, StatusCode};
use tungstenite::protocol::WebSocketConfig;
use crate::{error::Kind, RequestBuilder};
pub use tungstenite::Message;
use crate::Error;

/// Wrapper for [`RequestBuilder`] that performs the
/// websocket handshake when sent.
#[derive(Debug)]
pub struct UpgradedRequestBuilder {
    inner: RequestBuilder,
    nonce: String,
    protocols: Vec<String>,
    config: WebSocketConfig,
}

impl UpgradedRequestBuilder {
    pub(crate) fn new(inner: RequestBuilder) -> Self {
        let (nonce, inner) = {
            let nonce = tungstenite::handshake::client::generate_key();
            let inner = inner
                .header(header::CONNECTION, "upgrade")
                .header(header::UPGRADE, "websocket")
                .header(header::SEC_WEBSOCKET_KEY, &nonce)
                .header(header::SEC_WEBSOCKET_VERSION, "13");

            (nonce, inner)
        };

        Self {
            inner,
            nonce,
            protocols: vec![],
            config: WebSocketConfig::default(),
        }
    }

    /// Sets the websocket subprotocols to request.
    pub fn protocols(mut self, protocols: Vec<String>) -> Self {
        self.protocols.extend(protocols);
        self
    }

    /// Sets the websocket max_frame_size configuration.
    pub fn max_frame_size(mut self, max_frame_size: usize) -> Self {
        self.config.max_frame_size = Some(max_frame_size);
        self
    }

    /// Sets the websocket write_buffer_size configuration.
    pub fn write_buffer_size(mut self, write_buffer_size: usize) -> Self {
        self.config.write_buffer_size = write_buffer_size;
        self
    }

    /// Sets the websocket max_write_buffer_size configuration.
    pub fn max_write_buffer_size(mut self, max_write_buffer_size: usize) -> Self {
        self.config.max_write_buffer_size = max_write_buffer_size;
        self
    }

    /// Sets the websocket max_message_size configuration.
    pub fn max_message_size(mut self, max_message_size: usize) -> Self {
        self.config.max_message_size = Some(max_message_size);
        self
    }

    /// Sets the websocket accept_unmasked_frames configuration.
    pub fn accept_unmasked_frames(mut self, accept_unmasked_frames: bool) -> Self {
        self.config.accept_unmasked_frames = accept_unmasked_frames;
        self
    }

    /// Sends the request and returns and [`UpgradeResponse`].
    pub async fn send(self) -> Result<UpgradeResponse, Error> {
        #[cfg(not(target_arch = "wasm32"))]
        let inner = {
            let (client, request_result) = self.inner.build_split();
            let mut request = request_result?;

            // sets subprotocols
            if !self.protocols.is_empty() {
                let subprotocols = self.protocols
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<&str>>()
                    .join(", ");

                request.headers_mut()
                    .insert(header::SEC_WEBSOCKET_PROTOCOL, subprotocols.parse().map_err(|_| 
                        Error::new(Kind::Builder, Some("invalid subprotocol")))?);
            }

            // change the scheme from wss? to https?
            let url = request.url_mut();
            match url.scheme() {
                "ws" => {
                    url.set_scheme("http")
                        .expect("url should accept http scheme")
                }
                "wss" => {
                    url.set_scheme("https")
                        .expect("url should accept https scheme")
                }
                _ => {
                    Err(Error::new(Kind::Builder, Some("invalid scheme")))?;
                }
            }

            client.execute(request).await?
        };

        Ok(UpgradeResponse {
            inner,
            nonce: self.nonce,
            protocols: self.protocols,
            config: self.config,
        })
    }
}

/// The server's response to the websocket upgrade request.
///
/// This implements `Deref<Target = Response>`, so you can access all the usual
/// information from the [`Response`].
#[derive(Debug)]
pub struct UpgradeResponse {
    inner: crate::Response,
    nonce: String,
    protocols: Vec<String>,
    config: WebSocketConfig,
}

impl std::ops::Deref for UpgradeResponse {
    type Target = crate::Response;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl UpgradeResponse {
    /// Turns the response into a websocket. This checks if the websocket
    /// handshake was successful.
    pub async fn into_websocket(self) -> Result<WebSocket, Error> {
        let (inner, protocol) = {
            let headers = self.inner.headers();

            if self.inner.status() != StatusCode::SWITCHING_PROTOCOLS {
                return Err(Error::new(Kind::Status(self.res.status()), Some("unexpected status code")));
            }

            if !headers
                .get(header::CONNECTION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.eq_ignore_ascii_case("upgrade"))
                .unwrap_or_default()
            {
                return Err(Error::new(Kind::Status(self.res.status()), Some("missing connection upgrade")));
            }

            if !headers
                .get(header::UPGRADE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.eq_ignore_ascii_case("websocket"))
                .unwrap_or_default()
            {
                return Err(Error::new(Kind::Status(self.res.status()), Some("missing upgrade to websocket")));
            }

            let accept = headers
                .get(header::SEC_WEBSOCKET_ACCEPT)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(||Error::new(Kind::Status(self.res.status()), Some("invalid accept key")))?;
            
            // Check the accept key
            if accept != tungstenite::handshake::derive_accept_key(self.nonce.as_bytes()) {
                return Err(Error::new(Kind::Status(self.res.status()), Some("invalid accept key")));
            }

            let protocol = headers
                .get(header::SEC_WEBSOCKET_PROTOCOL)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_owned());

            match (self.protocols.is_empty(), &protocol) {
                (true, None) => {
                    // we didn't request any protocols, so we don't expect one
                    // in return
                }
                (false, None) => {
                    // server didn't reply with a protocol
                    return Err(Error::new(Kind::Status(self.res.status()), Some("missing protocol")));
                }
                (false, Some(protocol)) => {
                    if !self.protocols.contains(protocol) {
                        // the responded protocol is none which we requested
                        return Err(Error::new(Kind::Status(self.res.status()), Some("invalid protocol")));
                    }
                }
                (true, Some(_)) => {
                    // we didn't request any protocols but got one anyway
                    return Err(Error::new(Kind::Status(self.res.status()), Some("invalid protocol")));
                }
            }

            use tokio_util::compat::TokioAsyncReadCompatExt;

            let inner = async_tungstenite::WebSocketStream::from_raw_socket(
                self.inner.upgrade().await?.compat(),
                tungstenite::protocol::Role::Client,
                Some(self.config),
            )
            .await;

            (inner, protocol)
        };

        Ok(WebSocket { inner, protocol })
    }
}

/// A websocket connection
#[derive(Debug)]
pub struct WebSocket {
    inner: async_tungstenite::WebSocketStream<tokio_util::compat::Compat<crate::Upgraded>>,
    protocol: Option<String>,
}

impl WebSocket {
    /// Returns the subprotocol that the server has accepted.
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }
}

impl Stream for WebSocket {
    type Item = Result<Message, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.inner.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Some(Err(error.into()))),
                Poll::Ready(Some(Ok(message))) => {
                    return Poll::Ready(Some(Ok(message)))
                }
            }
        }
    }
}

impl Sink<Message> for WebSocket {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready_unpin(cx).map_err(Into::into)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.inner.start_send_unpin(item.into()).map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_flush_unpin(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_close_unpin(cx).map_err(Into::into)
    }
}
