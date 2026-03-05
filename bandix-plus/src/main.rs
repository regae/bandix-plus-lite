mod command;
mod ebpf;
mod options;
mod utils;

use clap::Parser;
use command::run;
use options::Options;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Options::parse();
    
    run(opt).await?;

    Ok(())
}
