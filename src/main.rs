mod builtin;
mod check;
mod cli;
mod describe;
mod init;
mod install;
mod manifest;
mod mcp;
mod paths;
mod registry;
mod runtime;
mod scaffold;
mod screen;
mod update;
mod vault;

use std::process::ExitCode;

fn main() -> ExitCode {
    let code = match cli::run() {
        Ok(code) => code,
        Err(err) => {
            cli::report_error(&format!("{err:#}"));
            ExitCode::FAILURE
        }
    };
    update::notify();
    code
}
