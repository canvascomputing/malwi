//! malwi: an agentic malware scanner for source trees and software packages.
//! The binary parses one command and hands it the rest of the arguments.

mod analyze;
mod attacks;
mod cli;
mod discovery;
mod download;
mod osint;
mod report;

use cli::Command;

#[tokio::main]
async fn main() {
    match Command::parse() {
        Command::Analyze(args) => analyze::run(args).await,
        Command::Osint(args) => osint::run(args).await,
        Command::Download(args) => download::run(args).await,
    }
}
