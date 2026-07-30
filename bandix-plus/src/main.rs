mod api;
mod command;
mod ebpf;
mod monitor;
mod options;
mod persistence;
mod policy;
mod topology;
mod utils;

use clap::Parser;
use command::run;
use options::Options;
use std::process::ExitCode;

/// 程序入口，解析命令行参数并启动主流程。
#[tokio::main]
async fn main() -> ExitCode {
    let opt = Options::parse();

    match run(opt).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bandix-plus fatal: {error:#}");
            ExitCode::FAILURE
        }
    }
}
