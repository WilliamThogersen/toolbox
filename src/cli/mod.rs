use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use serde::Serialize;
use serde_json::Value;

use crate::command::manifest::{ArgSpec, ArgType, Manifest};
use crate::cli::matches::{flag, optional};
use crate::command::registry::{self, CommandDef, Registry};
pub mod matches;
pub mod notice;
pub mod paths;
pub mod screen;

use crate::{builtin, runtime, vault};

pub fn run() -> Result<ExitCode> {
    let commands_dir = paths::commands_dir()?;
    let registry = registry::load(&commands_dir)?;
    let mut app = app(&registry);
    let matches = app.clone().get_matches();
    match matches.subcommand() {
        Some((builtin::NAMESPACE, m)) => builtin::run(m, &registry, &commands_dir),
        Some((name, m)) => run_user_command(&registry, name, m),
        None => {
            ignore_closed_pipe(app.print_help())?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn app(registry: &Registry) -> Command {
    let base = Command::new("toolbox")
        .version(env!("CARGO_PKG_VERSION"))
        .override_usage("tb <command> [args]")
        .help_template(help_template(registry))
        .disable_help_subcommand(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .help("Print help")
                .action(ArgAction::Help)
                .global(true)
                .hide(true),
        )
        .arg(Arg::new("version").short('V').long("version").action(ArgAction::Version).hide(true))
        .subcommand(builtin::app().hide(true));
    registry
        .commands
        .iter()
        .fold(base, |app, def| app.subcommand(user_app(&def.manifest)))
}

fn help_template(registry: &Registry) -> &'static str {
    if registry.commands.is_empty() {
        "{usage-heading} {usage}\n\nNo commands yet. Create one: tb self new <name>\n"
    } else {
        "{usage-heading} {usage}\n\n{all-args}\n\nManage commands and API keys: tb self\n"
    }
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

fn collect_args(manifest: &Manifest, matches: &ArgMatches) -> Result<Value> {
    let given = manifest
        .args
        .iter()
        .map(|(name, spec)| Ok(arg_value(name, spec, matches)?.map(|value| (name.clone(), value))))
        .collect::<Result<Vec<_>>>()?;
    Ok(Value::Object(given.into_iter().flatten().collect()))
}

fn arg_value(name: &str, spec: &ArgSpec, matches: &ArgMatches) -> Result<Option<Value>> {
    let given = match spec.kind {
        ArgType::Boolean => flag(matches, name)?.then_some(Value::Bool(true)),
        ArgType::String => optional(matches, name)?.map(Value::from),
        ArgType::Integer => matches.try_get_one::<i64>(name)?.map(|n| Value::from(*n)),
        ArgType::Number => matches.try_get_one::<f64>(name)?.map(|n| Value::from(*n)),
    };
    let fallback = || match spec.kind {
        ArgType::Boolean => Some(spec.default.clone().unwrap_or(Value::Bool(false))),
        _ => spec.default.clone(),
    };
    Ok(given.or_else(fallback))
}

fn run_user_command(registry: &Registry, name: &str, matches: &ArgMatches) -> Result<ExitCode> {
    let def: &CommandDef = registry
        .find(name)
        .with_context(|| format!("unknown command {name:?}"))?;
    let args = collect_args(&def.manifest, matches)?;
    let log = Box::new(vault::log::default_log()?);
    let output = runtime::run(def, &args, vault::default_store(), log)
        .with_context(|| format!("command {name:?} failed"))?;
    print_json(&output)
}

pub fn report_error(message: &str) {
    if io::stderr().is_terminal() {
        eprintln!("error: {message}");
    } else {
        eprintln!("{}", serde_json::json!({ "error": message }));
    }
}

pub fn print_json(value: &impl Serialize) -> Result<ExitCode> {
    let text = serde_json::to_string_pretty(value)? + "\n";
    ignore_closed_pipe(io::stdout().lock().write_all(text.as_bytes()))?;
    Ok(ExitCode::SUCCESS)
}

pub fn ignore_closed_pipe(result: io::Result<()>) -> Result<()> {
    match result {
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => Ok(other?),
    }
}
