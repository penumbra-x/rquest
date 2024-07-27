use boring::error::ErrorStack;
use boring::ssl::{SslConnectorBuilder, SslCurve};

/// Configure chrome to use the curves. (Chrome 123+)
pub fn configure_chrome_new_curves(builder: &mut SslConnectorBuilder) -> Result<(), ErrorStack> {
    builder.set_curves(&[
        SslCurve::X25519_KYBER768_DRAFT00,
        SslCurve::X25519,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
    ])
}
