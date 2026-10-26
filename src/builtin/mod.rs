mod app;
mod check;
mod describe;
mod init;
mod scaffold;
mod vault;

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::ArgMatches;
use serde_json::json;

pub use app::app;

use crate::cli::{ignore_closed_pipe, print_json};
use crate::install::{self, Confirm, Prompt, Yes, market};
use crate::cli::matches::{flag, optional, required, values};
use crate::command::registry::Registry;
use crate::cli::paths;
use crate::mcp;

pub const NAMESPACE: &str = "self";

pub fn run(matches: &ArgMatches, registry: &Registry, commands_dir: &Path) -> Result<ExitCode> {
    match matches.subcommand() {
        Some(("new", m)) => {
            let created = scaffold::create(commands_dir, required(m, "name")?, required(m, "description")?)?;
            print_json(&created)
        }
        Some(("check", _)) => {
            let report = check::check(registry);
            print_json(&report)?;
            Ok(if report.ok { ExitCode::SUCCESS } else { ExitCode::FAILURE })
        }
        Some(("describe", _)) => print_json(&describe::describe(registry, commands_dir)),
        Some(("guide", _)) => {
            ignore_closed_pipe(io::stdout().lock().write_all(describe::GUIDE.as_bytes()))?;
            Ok(ExitCode::SUCCESS)
        }
        Some(("install", m)) => install_command(commands_dir, m),
        Some(("search", m)) => print_json(&market::search(&paths::markets_file()?, commands_dir, optional(m, "text")?)?),
        Some(("market", m)) => market_command(commands_dir, m),
        Some(("update", m)) => {
            let report = install::update(commands_dir, optional(m, "name")?, confirmer(m)?)?;
            print_json(&report)?;
            Ok(if report.problems.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE })
        }
        Some(("uninstall", m)) => {
            let name = required(m, "name")?;
            install::uninstall(commands_dir, name)?;
            print_json(&json!({ "name": name, "uninstalled": true }))
        }
        Some(("vault", m)) => vault::run(m, registry),
        Some(("mcp", _)) => mcp::serve(commands_dir),
        Some(("init", m)) => init_command(m),
        _ => bail!("unknown `tb self` command. See `tb self --help`"),
    }
}

fn install_command(commands_dir: &Path, matches: &ArgMatches) -> Result<ExitCode> {
    let names = values(matches, "names")?;
    let markets = market::load(&paths::markets_file()?)?;
    let request = market::resolve(&markets, required(matches, "source")?, optional(matches, "ref")?, &names)?;
    if flag(matches, "list")? {
        return print_json(&install::list(commands_dir, &request.url, request.git_ref.as_deref())?);
    }
    print_json(&install::install(commands_dir, &request, confirmer(matches)?)?)
}

fn market_command(commands_dir: &Path, matches: &ArgMatches) -> Result<ExitCode> {
    let file = paths::markets_file()?;
    match matches.subcommand() {
        Some(("add", m)) => {
            let added = market::add(&file, commands_dir, required(m, "name")?, required(m, "url")?, optional(m, "ref")?)?;
            print_json(&added)
        }
        Some(("list", _)) => print_json(&market::entries(&file)?),
        Some(("rm", m)) => {
            let name = required(m, "name")?;
            market::remove(&file, name)?;
            print_json(&json!({ "name": name, "removed": true }))
        }
        _ => bail!("unknown `tb self market` command. See `tb self market --help`"),
    }
}

fn init_command(matches: &ArgMatches) -> Result<ExitCode> {
    let dir = paths::claude_dir()?;
    if flag(matches, "remove")? {
        return print_json(&init::remove(&dir)?);
    }
    let report = init::install(&dir)?;
    if let Some(note) = &report.note {
        eprintln!("{note}");
    }
    print_json(&report)
}

fn confirmer(matches: &ArgMatches) -> Result<&'static dyn Confirm> {
    Ok(if flag(matches, "yes")? { &Yes } else { &Prompt })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn every_builtin_is_documented() {
        let docs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs");
        let index = fs::read_to_string(docs.join("README.md")).unwrap();
        for cmd in app().get_subcommands() {
            let name = cmd.get_name();
            let page = format!("commands/{name}.md");
            let text = fs::read_to_string(docs.join(&page)).unwrap_or_else(|_| panic!("missing docs/{page}"));
            assert!(index.contains(&format!("({page})")), "docs/README.md does not link {page}");
            for sub in cmd.get_subcommands() {
                let usage = format!("tb self {name} {}", sub.get_name());
                assert!(text.contains(&usage), "docs/{page} does not show `{usage}`");
            }
            let flags = cmd.get_subcommands().chain([cmd]).flat_map(clap::Command::get_arguments);
            for long in flags.filter_map(|arg| arg.get_long()) {
                assert!(text.contains(&format!("--{long}")), "docs/{page} does not explain --{long}");
            }
        }
    }
}
