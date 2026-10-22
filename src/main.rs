mod check;
mod cli;
mod describe;
mod manifest;
mod paths;
mod registry;
mod runtime;
mod scaffold;
mod vault;

use std::io::IsTerminal;
use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::run() {
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
    }
}
