//! HTTP Client implementation and lower-level connection management.

mod body;
mod bounds;
mod dispatch;
mod pool;
mod proto;
mod service;

pub mod conn;
pub mod connect;
pub mod options;
pub mod upgrade;

pub(crate) use self::service::meta::{ConnectMeta, Identifier};
pub use self::{
    body::Incoming,
    service::{ConnectRequest, HttpClient, ResponseFuture, error::Error},
};
