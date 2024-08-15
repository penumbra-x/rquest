use async_tungstenite::tungstenite;

/// A `WebSocket` message, which can be a text string or binary data.
#[derive(Clone, Debug)]
pub enum Message {
    /// A text `WebSocket` message.
    Text(String),

    /// A binary `WebSocket` message.
    Binary(Vec<u8>),

    /// A ping message with the specified payload.
    ///
    /// The payload here must have a length less than 125 bytes.
    Ping(Vec<u8>),

    /// A pong message with the specified payload.
    ///
    /// The payload here must have a length less than 125 bytes.
    Pong(Vec<u8>),

    /// A close message.
    ///
    /// Sending this will not close the connection. Use [`WebSocket::close`] for this.
    /// Though the remote peer will likely close the connection after receiving this.
    ///
    /// [`WebSocket::close`]: crate::WebSocket::close
    Close {
        /// The close code.
        code: CloseCode,
        /// The reason for closing the connection.
        reason: Option<String>,
    },
}

impl From<String> for Message {
    #[inline]
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for Message {
    #[inline]
    fn from(value: &str) -> Self {
        Self::from(value.to_owned())
    }
}

impl From<Vec<u8>> for Message {
    #[inline]
    fn from(value: Vec<u8>) -> Self {
        Self::Binary(value)
    }
}

impl From<&[u8]> for Message {
    #[inline]
    fn from(value: &[u8]) -> Self {
        Self::from(value.to_vec())
    }
}

/// Status code used to indicate why an endpoint is closing the `WebSocket`
/// connection.[1]
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc6455
#[derive(Debug, Default, Eq, PartialEq, Clone, Copy)]
#[non_exhaustive]
pub enum CloseCode {
    /// Indicates a normal closure, meaning that the purpose for
    /// which the connection was established has been fulfilled.
    #[default]
    Normal,

    /// Indicates that an endpoint is "going away", such as a server
    /// going down or a browser having navigated away from a page.
    Away,

    /// Indicates that an endpoint is terminating the connection due
    /// to a protocol error.
    Protocol,

    /// Indicates that an endpoint is terminating the connection
    /// because it has received a type of data it cannot accept (e.g., an
    /// endpoint that understands only text data MAY send this if it
    /// receives a binary message).
    Unsupported,

    /// Indicates that no status code was included in a closing frame. This
    /// close code makes it possible to use a single method, `on_close` to
    /// handle even cases where no close code was provided.
    Status,

    /// Indicates an abnormal closure. If the abnormal closure was due to an
    /// error, this close code will not be used. Instead, the `on_error` method
    /// of the handler will be called with the error. However, if the connection
    /// is simply dropped, without an error, this close code will be sent to the
    /// handler.
    Abnormal,

    /// Indicates that an endpoint is terminating the connection
    /// because it has received data within a message that was not
    /// consistent with the type of the message (e.g., non-UTF-8 \[RFC3629\]
    /// data within a text message).
    Invalid,

    /// Indicates that an endpoint is terminating the connection
    /// because it has received a message that violates its policy.  This
    /// is a generic status code that can be returned when there is no
    /// other more suitable status code (e.g., Unsupported or Size) or if there
    /// is a need to hide specific details about the policy.
    Policy,

    /// Indicates that an endpoint is terminating the connection
    /// because it has received a message that is too big for it to
    /// process.
    Size,

    /// Indicates that an endpoint (client) is terminating the
    /// connection because it has expected the server to negotiate one or
    /// more extension, but the server didn't return them in the response
    /// message of the `WebSocket` handshake.  The list of extensions that
    /// are needed should be given as the reason for closing.
    /// Note that this status code is not used by the server, because it
    /// can fail the `WebSocket` handshake instead.
    Extension,

    /// Indicates that a server is terminating the connection because
    /// it encountered an unexpected condition that prevented it from
    /// fulfilling the request.
    Error,

    /// Indicates that the server is restarting. A client may choose to
    /// reconnect, and if it does, it should use a randomized delay of 5-30
    /// seconds between attempts.
    Restart,

    /// Indicates that the server is overloaded and the client should either
    /// connect to a different IP (when multiple targets exist), or
    /// reconnect to the same IP when a user has performed an action.
    Again,

    /// Indicates that the connection was closed due to a failure to perform a
    /// TLS handshake (e.g., the server certificate can't be verified). This
    /// is a reserved value and MUST NOT be set as a status code in a Close
    /// control frame by an endpoint.
    Tls,

    /// Reserved status codes.
    Reserved(u16),

    /// Reserved for use by libraries, frameworks, and applications. These
    /// status codes are registered directly with IANA. The interpretation of
    /// these codes is undefined by the `WebSocket` protocol.
    Iana(u16),

    /// Reserved for private use. These can't be registered and can be used by
    /// prior agreements between `WebSocket` applications. The interpretation of
    /// these codes is undefined by the `WebSocket` protocol.
    Library(u16),

    /// Unused / invalid status codes.
    Bad(u16),
}

impl CloseCode {
    /// Check if this `CloseCode` is allowed.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        !matches!(
            self,
            Self::Bad(_) | Self::Reserved(_) | Self::Status | Self::Abnormal | Self::Tls
        )
    }
}

impl std::fmt::Display for CloseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let code: u16 = (*self).into();
        write!(f, "{code}")
    }
}

impl From<CloseCode> for u16 {
    fn from(code: CloseCode) -> Self {
        match code {
            CloseCode::Normal => 1000,
            CloseCode::Away => 1001,
            CloseCode::Protocol => 1002,
            CloseCode::Unsupported => 1003,
            CloseCode::Status => 1005,
            CloseCode::Abnormal => 1006,
            CloseCode::Invalid => 1007,
            CloseCode::Policy => 1008,
            CloseCode::Size => 1009,
            CloseCode::Extension => 1010,
            CloseCode::Error => 1011,
            CloseCode::Restart => 1012,
            CloseCode::Again => 1013,
            CloseCode::Tls => 1015,
            CloseCode::Reserved(code)
            | CloseCode::Iana(code)
            | CloseCode::Library(code)
            | CloseCode::Bad(code) => code,
        }
    }
}

impl From<u16> for CloseCode {
    fn from(code: u16) -> Self {
        match code {
            1000 => Self::Normal,
            1001 => Self::Away,
            1002 => Self::Protocol,
            1003 => Self::Unsupported,
            1005 => Self::Status,
            1006 => Self::Abnormal,
            1007 => Self::Invalid,
            1008 => Self::Policy,
            1009 => Self::Size,
            1010 => Self::Extension,
            1011 => Self::Error,
            1012 => Self::Restart,
            1013 => Self::Again,
            1015 => Self::Tls,
            1016..=2999 => Self::Reserved(code),
            3000..=3999 => Self::Iana(code),
            4000..=4999 => Self::Library(code),
            _ => Self::Bad(code),
        }
    }
}

impl From<tungstenite::protocol::frame::coding::CloseCode> for CloseCode {
    fn from(value: tungstenite::protocol::frame::coding::CloseCode) -> Self {
        u16::from(value).into()
    }
}

impl From<CloseCode> for tungstenite::protocol::frame::coding::CloseCode {
    fn from(value: CloseCode) -> Self {
        u16::from(value).into()
    }
}
