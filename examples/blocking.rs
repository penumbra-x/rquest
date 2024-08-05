//! `cargo run --example blocking --features=blocking`
#![deny(warnings)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Some simple CLI args requirements...
    let url = match std::env::args().nth(1) {
        Some(url) => url,
        None => {
            println!("No CLI URL provided, using default.");
            "https://hyper.rs".into()
        }
    };

    eprintln!("Fetching {:?}...", url);

    // rquest::blocking::get() is a convenience function.
    //
    // In most cases, you should create/build a rquest::Client and reuse
    // it for all requests.
    let mut res = rquest::blocking::get(url)?;

    eprintln!("Response: {:?} {}", res.version(), res.status());
    eprintln!("Headers: {:#?}\n", res.headers());

    // copy the response body directly to stdout
    res.copy_to(&mut std::io::stdout())?;

    Ok(())
}
