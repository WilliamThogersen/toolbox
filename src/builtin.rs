//! `tb self ...`: everything that manages the toolbox rather than being a tool.
//! Kept out of the top-level list so `tb` only shows the user's own commands.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Arg, ArgAction, ArgMatches, Command};

use crate::cli::{ignore_closed_pipe, print_json};
use crate::registry::Registry;
use crate::install::{self, Confirm, Prompt, Yes};
use crate::vault::commands::{self as vault_ops, Tty};
use crate::{check, describe, scaffold, vault};

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
                .about("Install the commands in a git repo (GitHub, GitLab or any git URL)")
                .arg(Arg::new("url").required(true).help("Git URL, e.g. https://github.com/you/tb-tools.git"))
                .arg(
                    Arg::new("ref")
                        .long("ref")
                        .help("Branch, tag or commit to install (default: the repo's default branch)"),
                )
                .arg(yes_arg()),
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
        .subcommand(vault_app())
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
                .about("Add or replace a secret. Prompts for the value, so a human must run it in a terminal")
                .arg(Arg::new("name").required(true))
                .arg(
                    Arg::new("host")
                        .long("host")
                        .required(true)
                        .action(ArgAction::Append)
                        .value_delimiter(',')
                        .help("Host the secret may be sent to, e.g. api.github.com (repeatable)"),
                ),
        )
        .subcommand(Command::new("list").about("Secret names and allowed hosts (never values)"))
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
        Some(("install", m)) => {
            let url = m.get_one::<String>("url").expect("required");
            let git_ref = m.get_one::<String>("ref").map(String::as_str);
            print_json(&install::install(commands_dir, url, git_ref, confirmer(m))?)
        }
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
        Some(("vault", m)) => vault_command(m),
        _ => unreachable!("clap requires a `self` subcommand"),
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

fn vault_command(matches: &ArgMatches) -> Result<ExitCode> {
    let store = vault::default_store();
    match matches.subcommand() {
        Some(("add", m)) => {
            let name = m.get_one::<String>("name").expect("required");
            let hosts: Vec<String> = m.get_many::<String>("host").into_iter().flatten().cloned().collect();
            print_json(&vault_ops::add(store.as_ref(), &Tty, name, &hosts)?)
        }
        Some(("list", _)) => print_json(&vault_ops::list(store.as_ref())?),
        Some(("rm", m)) => {
            let name = m.get_one::<String>("name").expect("required");
            let deleted = vault_ops::remove(store.as_ref(), &Tty, name)?;
            print_json(&serde_json::json!({ "name": name, "deleted": deleted }))
        }
        _ => unreachable!("clap requires a vault subcommand"),
    }
}
