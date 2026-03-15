mod api;
mod command;
mod ebpf;
mod monitor;
mod options;
mod policy;
mod topology;
mod utils;

use clap::Parser;
use command::run;
use options::Options;

/// 程序入口，解析命令行参数并启动主流程。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Options::parse();
    
    run(opt).await?;

    Ok(())
}
