//! malwi: an agentic malware scanner for source trees and software packages.
//! The binary parses one command and hands it the rest of the arguments.

mod attacks;
mod cli;
mod discovery;
mod osint;
mod report;
mod scan;

use cli::Command;

#[tokio::main]
async fn main() {
    match Command::parse() {
        Command::Scan(args) => scan::run(args).await,
        Command::Osint(args) => osint::run(args).await,
    }
}
