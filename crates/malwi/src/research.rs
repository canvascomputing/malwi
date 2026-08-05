//! The `research` command: turns a security question into a researched answer.

use crate::cli::ResearchArgs;

/// Stop the run until the research chain lands, echoing the parsed question so
/// the operator sees what would have been asked.
pub(crate) fn run(args: ResearchArgs) -> ! {
    eprintln!("malwi research: not yet implemented");
    eprintln!("question: {}", args.question);
    std::process::exit(1);
}
