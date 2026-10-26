mod builtin;
mod cli;
mod command;
mod install;
mod mcp;
mod runtime;
mod sys;
mod vault;

use std::process::ExitCode;

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|info| cli::report_error(&format!("internal error, please report it: {info}"))));
    if let Err(err) = sys::stop_children_on_termination() {
        cli::report_error(&format!("could not set up signal handling: {err}"));
        return ExitCode::FAILURE;
    }
    let code = match cli::run() {
        Ok(code) => code,
        Err(err) => {
            cli::report_error(&format!("{err:#}"));
            ExitCode::FAILURE
        }
    };
    cli::notice::notify();
    code
}
