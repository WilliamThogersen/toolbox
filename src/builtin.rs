//! `tb self ...`: everything that manages the toolbox rather than being a tool.
//! Kept out of the top-level list so `tb` only shows the user's own commands.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Arg, ArgAction, ArgMatches, Command};

use crate::cli::{ignore_closed_pipe, print_json};
use crate::install::{self, Confirm, Prompt, Yes, market};
use crate::registry::Registry;
use crate::vault::commands::{self as vault_ops, Rules, Tty};
use crate::{check, describe, paths, scaffold, vault};

pub const NAMESPACE: &str = "self";

pub fn app() -> Command {
    Command::new(NAMESPACE)
        .about("Manage toolbox: create, install and check commands, store API keys")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .disable_help_subcommand(true)
        .subcommand(
            Command::new("new")
                .about("Create a new command from a template")
                .arg(Arg::new("name").required(true))
                .arg(
                    Arg::new("description")
                        .long("description")
                        .default_value("TODO: describe what this command does"),
                ),
        )
        .subcommand(Command::new("check").about("Validate every command; exits 1 if anything is broken"))
        .subcommand(Command::new("describe").about("List every command, its args and permissions, as JSON"))
        .subcommand(Command::new("guide").about("How to write new commands (manifest format and Lua API)"))
        .subcommand(
            Command::new("install")
                .about("Install commands from a git repo (GitHub, GitLab or any git URL) or a saved marketplace")
                .arg(
                    Arg::new("source")
                        .required(true)
                        .help("Git URL, local repo path, or saved marketplace: acme or acme/stars"),
                )
                .arg(
                    Arg::new("names")
                        .num_args(0..)
                        .help("Only install these commands (default: every working command in the repo)"),
                )
                .arg(ref_arg())
                .arg(
                    Arg::new("list")
                        .long("list")
                        .action(ArgAction::SetTrue)
                        .help("Show the repo's commands and permissions as JSON, install nothing"),
                )
                .arg(yes_arg()),
        )
        .subcommand(
            Command::new("search")
                .about("Search the commands in every saved marketplace")
                .arg(Arg::new("text").help("Words in the name or description (default: list everything)")),
        )
        .subcommand(
            Command::new("update")
                .about("Update installed commands to the newest version in their repo")
                .arg(Arg::new("name").help("Only update this command (default: every installed command)"))
                .arg(yes_arg()),
        )
        .subcommand(
            Command::new("uninstall")
                .about("Remove a command that was added with `tb self install`")
                .arg(Arg::new("name").required(true)),
        )
        .subcommand(market_app())
        .subcommand(vault_app())
}

fn market_app() -> Command {
    Command::new("market")
        .about("Saved marketplaces: git repos of commands you can search and install by name")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .disable_help_subcommand(true)
        .subcommand(
            Command::new("add")
                .about("Save a repo of commands under a short name")
                .arg(Arg::new("name").required(true).help("Short name, used as <name>/<command>"))
                .arg(Arg::new("url").required(true).help("Git URL or local repo path"))
                .arg(ref_arg()),
        )
        .subcommand(Command::new("list").about("Saved marketplaces and their URLs"))
        .subcommand(
            Command::new("rm")
                .about("Forget a marketplace. Commands installed from it stay")
                .arg(Arg::new("name").required(true)),
        )
}

fn ref_arg() -> Arg {
    Arg::new("ref")
        .long("ref")
        .help("Branch, tag or commit to use (default: the repo's default branch)")
}

fn yes_arg() -> Arg {
    Arg::new("yes")
        .long("yes")
        .short('y')
        .action(ArgAction::SetTrue)
        .help("Don't ask before installing code from the repo (for scripts and agents)")
}

fn vault_app() -> Command {
    Command::new("vault")
        .about("API keys that commands can use without ever seeing them")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .disable_help_subcommand(true)
        .subcommand(
            Command::new("add")
                .about("Add a secret or change where it may go. Prompts for the value (empty keeps the current one), so a human must run it in a terminal")
                .arg(Arg::new("name").required(true))
                .arg(
                    Arg::new("host")
                        .long("host")
                        .required(true)
                        .action(ArgAction::Append)
                        .value_delimiter(',')
                        .help("Host the secret may be sent to, e.g. api.github.com or 127.0.0.1:8080 (repeatable)"),
                )
                .arg(
                    Arg::new("query-param")
                        .long("query-param")
                        .action(ArgAction::Append)
                        .value_delimiter(',')
                        .help("Query parameter it may also be sent in, e.g. key for ?key=... (repeatable)"),
                ),
        )
        .subcommand(Command::new("list").about("Secrets, where they may go and which commands use them (never values)"))
        .subcommand(
            Command::new("allow")
                .about("Let a command use a secret. Shows its script and asks in a terminal")
                .arg(Arg::new("secret").required(true))
                .arg(Arg::new("command").required(true)),
        )
        .subcommand(
            Command::new("revoke")
                .about("Stop a command from using a secret. Asks in a terminal")
                .arg(Arg::new("secret").required(true))
                .arg(Arg::new("command").required(true)),
        )
        .subcommand(
            Command::new("rm")
                .about("Delete a secret. Asks for confirmation in a terminal")
                .arg(Arg::new("name").required(true)),
        )
}

pub fn run(matches: &ArgMatches, registry: &Registry, commands_dir: &Path) -> Result<ExitCode> {
    match matches.subcommand() {
        Some(("new", m)) => new_command(commands_dir, m),
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
        Some(("search", m)) => {
            let text = m.get_one::<String>("text").map(String::as_str);
            print_json(&market::search(&paths::markets_file()?, commands_dir, text)?)
        }
        Some(("market", m)) => market_command(commands_dir, m),
        Some(("update", m)) => {
            let name = m.get_one::<String>("name").map(String::as_str);
            let report = install::update(commands_dir, name, confirmer(m))?;
            print_json(&report)?;
            Ok(if report.problems.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE })
        }
        Some(("uninstall", m)) => {
            let name = m.get_one::<String>("name").expect("required");
            install::uninstall(commands_dir, name)?;
            print_json(&serde_json::json!({ "name": name, "uninstalled": true }))
        }
        Some(("vault", m)) => vault_command(m, registry),
        _ => unreachable!("clap requires a `self` subcommand"),
    }
}

fn install_command(commands_dir: &Path, matches: &ArgMatches) -> Result<ExitCode> {
    let source = matches.get_one::<String>("source").expect("required");
    let names: Vec<String> = matches.get_many::<String>("names").into_iter().flatten().cloned().collect();
    let git_ref = matches.get_one::<String>("ref").map(String::as_str);
    let markets = market::load(&paths::markets_file()?)?;
    let request = market::resolve(&markets, source, git_ref, &names)?;
    if matches.get_flag("list") {
        return print_json(&install::list(commands_dir, &request.url, request.git_ref.as_deref())?);
    }
    print_json(&install::install(commands_dir, &request, confirmer(matches))?)
}

fn market_command(commands_dir: &Path, matches: &ArgMatches) -> Result<ExitCode> {
    let file = paths::markets_file()?;
    match matches.subcommand() {
        Some(("add", m)) => {
            let name = m.get_one::<String>("name").expect("required");
            let url = m.get_one::<String>("url").expect("required");
            let git_ref = m.get_one::<String>("ref").map(String::as_str);
            print_json(&market::add(&file, commands_dir, name, url, git_ref)?)
        }
        Some(("list", _)) => print_json(&market::entries(&file)?),
        Some(("rm", m)) => {
            let name = m.get_one::<String>("name").expect("required");
            market::remove(&file, name)?;
            print_json(&serde_json::json!({ "name": name, "removed": true }))
        }
        _ => unreachable!("clap requires a market subcommand"),
    }
}

fn confirmer(matches: &ArgMatches) -> &'static dyn Confirm {
    if matches.get_flag("yes") { &Yes } else { &Prompt }
}

fn new_command(commands_dir: &Path, matches: &ArgMatches) -> Result<ExitCode> {
    let name = matches.get_one::<String>("name").expect("required");
    let description = matches.get_one::<String>("description").expect("has default");
    let created = scaffold::create(commands_dir, name, description)?;
    print_json(&created)
}

fn vault_command(matches: &ArgMatches, registry: &Registry) -> Result<ExitCode> {
    let store = vault::default_store();
    let pair = |m: &ArgMatches| {
        let get = |id| m.get_one::<String>(id).expect("required").clone();
        (get("secret"), get("command"))
    };
    match matches.subcommand() {
        Some(("add", m)) => {
            let name = m.get_one::<String>("name").expect("required");
            let values = |id| m.get_many::<String>(id).into_iter().flatten().cloned().collect::<Vec<_>>();
            let (hosts, query_params) = (values("host"), values("query-param"));
            let rules = Rules { hosts: &hosts, query_params: &query_params };
            let summary = vault_ops::add(store.as_ref(), &Tty, registry, name, rules)?;
            if let Some(note) = vault::hosts::local_note(&summary.hosts) {
                eprintln!("{note}");
            }
            print_json(&summary)
        }
        Some(("list", _)) => print_json(&vault_ops::list(store.as_ref(), registry)?),
        Some(("allow", m)) => {
            let (secret, command) = pair(m);
            let allowed = vault_ops::allow(store.as_ref(), &Tty, registry, &secret, &command)?;
            print_json(&serde_json::json!({ "secret": secret, "command": command, "allowed": allowed }))
        }
        Some(("revoke", m)) => {
            let (secret, command) = pair(m);
            let revoked = vault_ops::revoke(store.as_ref(), &Tty, &secret, &command)?;
            print_json(&serde_json::json!({ "secret": secret, "command": command, "revoked": revoked }))
        }
        Some(("rm", m)) => {
            let name = m.get_one::<String>("name").expect("required");
            let deleted = vault_ops::remove(store.as_ref(), &Tty, name)?;
            print_json(&serde_json::json!({ "name": name, "deleted": deleted }))
        }
        _ => unreachable!("clap requires a vault subcommand"),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    /// Every `tb self` command needs a page in docs/commands/ that names its subcommands and flags.
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
            let flags = cmd.get_subcommands().chain([cmd]).flat_map(|c| c.get_arguments());
            for long in flags.filter_map(|arg| arg.get_long()) {
                assert!(text.contains(&format!("--{long}")), "docs/{page} does not explain --{long}");
            }
        }
    }
}
