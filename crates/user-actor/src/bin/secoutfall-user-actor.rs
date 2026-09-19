//! Composition root for the `SecOutfall` user-actor (phase 0 stub).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("{} v{}", user_actor::NAME, env!("CARGO_PKG_VERSION"));
    Ok(())
}
