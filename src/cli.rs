//! Builds the clap app from built-ins plus every loaded command, then dispatches.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::manifest::{ArgSpec, ArgType, Manifest};
use crate::registry::{self, CommandDef, Registry};
use crate::vault::commands::{self as vault_ops, Tty};
use crate::{check, describe, paths, runtime, scaffold, vault};

pub fn run() -> Result<ExitCode> {
    let commands_dir = paths::commands_dir()?;
    let registry = registry::load(&commands_dir)?;
    let matches = app(&registry).get_matches();
    match matches.subcommand() {
        Some(("describe", _)) => print_json(&describe::describe(&registry, &commands_dir)),
        Some(("guide", _)) => {
            print!("{}", describe::GUIDE);
            Ok(ExitCode::SUCCESS)
        }
        Some(("new", m)) => new_command(&commands_dir, m),
        Some(("check", _)) => {
            let report = check::check(&registry);
            print_json(&report)?;
            Ok(if report.ok { ExitCode::SUCCESS } else { ExitCode::FAILURE })
        }
        Some(("vault", m)) => vault_command(m),
        Some((name, m)) => run_user_command(&registry, name, m),
        None => unreachable!("clap requires a subcommand"),
    }
}

fn app(registry: &Registry) -> Command {
    let base = Command::new("toolbox")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A toolbox CLI that grows with JSON + Lua commands. Start with `tb describe` and `tb guide`.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("describe").about("List every command, its args and permissions, as JSON"))
        .subcommand(Command::new("guide").about("How to write new commands (manifest format and Lua API)"))
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
        .subcommand(vault_app());
    registry
        .commands
        .iter()
        .fold(base, |app, def| app.subcommand(user_app(&def.manifest)))
}

fn vault_app() -> Command {
    Command::new("vault")
        .about("API keys that commands can use without ever seeing them")
        .subcommand_required(true)
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

fn user_app(manifest: &Manifest) -> Command {
    manifest.args.iter().fold(
        Command::new(manifest.name.clone()).about(manifest.description.clone()),
        |cmd, (name, spec)| cmd.arg(user_arg(name, spec)),
    )
}

fn user_arg(name: &str, spec: &ArgSpec) -> Arg {
    let arg = Arg::new(name.to_string())
        .long(name.to_string())
        .help(spec.description.clone());
    match spec.kind {
        ArgType::Boolean => arg.action(ArgAction::SetTrue),
        ArgType::String => arg.required(spec.required).value_parser(value_parser!(String)),
        ArgType::Integer => arg.required(spec.required).value_parser(value_parser!(i64)),
        ArgType::Number => arg.required(spec.required).value_parser(value_parser!(f64)),
    }
}

fn collect_args(manifest: &Manifest, matches: &ArgMatches) -> Value {
    let args: Map<String, Value> = manifest
        .args
        .iter()
        .filter_map(|(name, spec)| arg_value(name, spec, matches).map(|v| (name.clone(), v)))
        .collect();
    Value::Object(args)
}

fn arg_value(name: &str, spec: &ArgSpec, matches: &ArgMatches) -> Option<Value> {
    let given = match spec.kind {
        ArgType::Boolean => matches.get_flag(name).then_some(Value::Bool(true)),
        ArgType::String => matches.get_one::<String>(name).map(|s| Value::from(s.clone())),
        ArgType::Integer => matches.get_one::<i64>(name).map(|n| Value::from(*n)),
        ArgType::Number => matches.get_one::<f64>(name).map(|n| Value::from(*n)),
    };
    let fallback = || match spec.kind {
        ArgType::Boolean => Some(spec.default.clone().unwrap_or(Value::Bool(false))),
        _ => spec.default.clone(),
    };
    given.or_else(fallback)
}

fn run_user_command(registry: &Registry, name: &str, matches: &ArgMatches) -> Result<ExitCode> {
    let def: &CommandDef = registry
        .find(name)
        .with_context(|| format!("unknown command {name:?}"))?;
    let args = collect_args(&def.manifest, matches);
    let output = runtime::run(def, &args, vault::default_store())
        .with_context(|| format!("command {name:?} failed"))?;
    print_json(&output)
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

fn print_json(value: &impl Serialize) -> Result<ExitCode> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(ExitCode::SUCCESS)
}
