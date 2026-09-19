//! Composition root for the `SecOutfall` agent (console mode in phase 0; SCM
//! service wiring lands with the windows-service adapter, phase 5).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("{} v{}", agent::NAME, env!("CARGO_PKG_VERSION"));
    Ok(())
}
