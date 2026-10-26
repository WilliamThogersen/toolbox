use std::io::{self, IsTerminal};
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::ArgMatches;
use serde_json::json;

use crate::cli::print_json;
use crate::cli::matches::{flag, optional, required, typed, values};
use crate::command::registry::Registry;
use crate::vault::activity::{Follower, Style, print_line, render};
use crate::vault::commands::{self as vault_ops, Rules, Tty};
use crate::vault::log::{FileLog, Filter};
use crate::vault::oauth::TokenCache;
use crate::vault::oauth::login::{SignIn, SystemBrowser, Tools, sign_in};
use crate::vault::requests::KeyRequest;
use crate::vault::{self, VaultStore};

struct Context<'a> {
    store: Box<dyn VaultStore>,
    log: FileLog,
    registry: &'a Registry,
}

pub fn run(matches: &ArgMatches, registry: &Registry) -> Result<ExitCode> {
    let cx = Context { store: vault::default_store(), log: vault::log::default_log()?, registry };
    match matches.subcommand() {
        Some(("add", m)) => add(&cx, m),
        Some(("request", m)) => request(&cx, m),
        Some(("oauth", m)) => oauth(&cx, m),
        Some(("setup", m)) => setup(&cx, m),
        Some(("list", _)) => print_json(&vault_ops::list(cx.store.as_ref(), registry)?),
        Some(("allow", m)) => {
            let (secret, command) = (required(m, "secret")?, required(m, "command")?);
            let allowed = vault_ops::allow(cx.store.as_ref(), &cx.log, &Tty, registry, secret, command)?;
            print_json(&json!({ "secret": secret, "command": command, "allowed": allowed }))
        }
        Some(("revoke", m)) => {
            let (secret, command) = (required(m, "secret")?, required(m, "command")?);
            let revoked = vault_ops::revoke(cx.store.as_ref(), &cx.log, &Tty, secret, command)?;
            print_json(&json!({ "secret": secret, "command": command, "revoked": revoked }))
        }
        Some(("rm", m)) => {
            let name = required(m, "name")?;
            let deleted = vault_ops::remove(cx.store.as_ref(), &cx.log, &Tty, name)?;
            if deleted && let Err(err) = TokenCache::in_home().and_then(|cache| cache.forget(name)) {
                eprintln!("toolbox: the key is deleted, but its saved sign-in tokens are still on disk (encrypted): {err:#}");
            }
            print_json(&json!({ "name": name, "deleted": deleted }))
        }
        Some(("log", m)) => log(&cx, m),
        _ => bail!("unknown `tb self vault` command. See `tb self vault --help`"),
    }
}

fn add(cx: &Context, m: &ArgMatches) -> Result<ExitCode> {
    let (hosts, query_params) = (values(m, "host")?, values(m, "query-param")?);
    let (methods, paths, confirm) = (values(m, "method")?, values(m, "path")?, values(m, "confirm")?);
    let rules = Rules { hosts: &hosts, query_params: &query_params, methods: &methods, paths: &paths, confirm: &confirm };
    let summary = vault_ops::add(cx.store.as_ref(), &cx.log, &Tty, cx.registry, required(m, "name")?, rules)?;
    if let Some(note) = vault::hosts::local_note(&summary.hosts) {
        eprintln!("{note}");
    }
    print_json(&summary)
}

fn oauth(cx: &Context, m: &ArgMatches) -> Result<ExitCode> {
    let (hosts, query_params) = (values(m, "host")?, values(m, "query-param")?);
    let (methods, paths, confirm) = (values(m, "method")?, values(m, "path")?, values(m, "confirm")?);
    let (scopes, auth_params) = (values(m, "scope")?, values(m, "auth-param")?);
    let request = SignIn {
        name: required(m, "name")?,
        rules: Rules { hosts: &hosts, query_params: &query_params, methods: &methods, paths: &paths, confirm: &confirm },
        auth_url: optional(m, "auth-url")?,
        token_url: optional(m, "token-url")?,
        client_id: optional(m, "client-id")?,
        scopes: &scopes,
        auth_params: &auth_params,
        port: m.try_get_one::<u16>("port")?.copied(),
    };
    let cache = TokenCache::in_home()?;
    let tools = Tools {
        store: cx.store.as_ref(),
        log: &cx.log,
        term: &Tty,
        browser: &SystemBrowser,
        cache: &cache,
        registry: cx.registry,
    };
    print_json(&sign_in(&tools, &request)?)
}

fn request(cx: &Context, m: &ArgMatches) -> Result<ExitCode> {
    let wanted = KeyRequest::new(
        required(m, "name")?,
        &values(m, "host")?,
        &values(m, "query-param")?,
        required(m, "why")?,
        optional(m, "note")?,
    )?
    .limited_to(&values(m, "method")?, &values(m, "path")?)?;
    let path = vault::requests::default_path()?;
    print_json(&vault::requests::request(cx.store.as_ref(), &cx.log, cx.registry, &path, wanted)?)
}

fn setup(cx: &Context, m: &ArgMatches) -> Result<ExitCode> {
    let path = vault::requests::default_path()?;
    let only = optional(m, "command")?;
    let report = vault::setup::setup(cx.store.as_ref(), &cx.log, &Tty, cx.registry, &path, only)?;
    if report.is_empty() {
        eprintln!("Nothing is waiting: no key requests, and every command that uses a key is allowed.");
    }
    print_json(&report)
}

fn log(cx: &Context, m: &ArgMatches) -> Result<ExitCode> {
    let filter = Filter {
        key: optional(m, "key")?,
        command: optional(m, "command")?,
        limit: typed::<usize>(m, "limit")?,
    };
    let (pretty, follow) = (flag(m, "pretty")?, flag(m, "follow")?);
    if !pretty && !follow {
        return print_json(&vault::log::read(&cx.log.path, &filter)?);
    }
    let style = match pretty {
        false => Style::Json,
        true if io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() => Style::Color,
        true => Style::Plain,
    };
    let follower = Follower { path: cx.log.path.clone(), filter: &filter, style };
    let start = follower.start();
    let mut entries = vault::log::read(&cx.log.path, &filter)?;
    entries.reverse();
    if entries.is_empty() && !follow {
        eprintln!("No key activity yet.");
    }
    for entry in &entries {
        if !print_line(&render(entry, style))? {
            return Ok(ExitCode::SUCCESS);
        }
    }
    if follow {
        follower.run(start, &mut print_line)?;
    }
    Ok(ExitCode::SUCCESS)
}
