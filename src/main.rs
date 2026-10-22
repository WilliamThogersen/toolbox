mod builtin;
mod check;
mod cli;
mod describe;
mod install;
mod manifest;
mod paths;
mod registry;
mod runtime;
mod scaffold;
mod update;
mod vault;

use std::io::IsTerminal;
use std::process::ExitCode;

fn main() -> ExitCode {
    let code = match cli::run() {
        Ok(code) => code,
        Err(err) => {
            let message = format!("{err:#}");
            if std::io::stderr().is_terminal() {
                eprintln!("error: {message}");
            } else {
                eprintln!("{}", serde_json::json!({ "error": message }));
            }
            ExitCode::FAILURE
        }
    };
    update::notify();
    code
}
