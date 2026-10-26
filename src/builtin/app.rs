use clap::{Arg, ArgAction, Command};

use super::NAMESPACE;

pub fn app() -> Command {
    group(NAMESPACE, "Manage toolbox: create, install and check commands, store API keys")
        .subcommand(new_app())
        .subcommand(Command::new("check").about("Validate every command; exits 1 if anything is broken"))
        .subcommand(
            Command::new("describe").about("List every command, its args and permissions, as JSON").arg(
                Arg::new("origin")
                    .long("origin")
                    .action(ArgAction::SetTrue)
                    .help("Also say where each command came from and whether it was edited since install"),
            ),
        )
        .subcommand(Command::new("guide").about("How to write new commands (manifest format and Lua API)"))
        .subcommand(install_app())
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
        .subcommand(Command::new("mcp").about("Serve your commands as MCP tools over stdio, for Claude Code and other AI apps"))
        .subcommand(init_app())
}

fn group(name: &'static str, about: &'static str) -> Command {
    Command::new(name)
        .about(about)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .disable_help_subcommand(true)
}

fn new_app() -> Command {
    Command::new("new")
        .about("Create a new command from a template")
        .arg(Arg::new("name").required(true))
        .arg(
            Arg::new("description")
                .long("description")
                .default_value("TODO: describe what this command does"),
        )
}

fn install_app() -> Command {
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
        .arg(yes_arg())
}

fn init_app() -> Command {
    Command::new("init")
        .about("Tell Claude Code about toolbox: writes ~/.claude/TOOLBOX.md and imports it from CLAUDE.md")
        .arg(
            Arg::new("remove")
                .long("remove")
                .action(ArgAction::SetTrue)
                .help("Take it out again: removes the import and TOOLBOX.md"),
        )
}

fn market_app() -> Command {
    group("market", "Saved marketplaces: git repos of commands you can search and install by name")
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
    group("vault", "API keys that commands can use without ever seeing them")
        .subcommand(
            Command::new("add")
                .about("Add a secret or change where it may go. Prompts for the value (empty keeps the current one), so a human must run it in a terminal")
                .arg(key_name_arg())
                .arg(host_arg())
                .arg(query_param_arg())
                .arg(method_arg())
                .arg(path_arg())
                .arg(confirm_arg()),
        )
        .subcommand(vault_request_app())
        .subcommand(vault_oauth_app())
        .subcommand(
            Command::new("setup")
                .about("Add the keys agents asked for and allow the commands waiting for a key, with one Touch ID")
                .arg(Arg::new("command").help("Only this command. Also asks for keys it lists that nobody requested")),
        )
        .subcommand(Command::new("list").about("Secrets, where they may go and which commands use them (never values)"))
        .subcommand(grant_app("allow", "Let a command use a secret. Shows its script and asks in a terminal"))
        .subcommand(grant_app("revoke", "Stop a command from using a secret. Asks in a terminal"))
        .subcommand(
            Command::new("rm")
                .about("Delete a secret. Asks for confirmation in a terminal")
                .arg(Arg::new("name").required(true)),
        )
        .subcommand(vault_log_app())
}

fn vault_request_app() -> Command {
    Command::new("request")
        .about("Ask the user for a key. Needs no terminal: an agent runs it, then asks the user to run `tb self vault setup`")
        .arg(key_name_arg())
        .arg(host_arg())
        .arg(query_param_arg())
        .arg(method_arg())
        .arg(path_arg())
        .arg(
            Arg::new("why")
                .long("why")
                .required(true)
                .help("What the key is needed for, shown to the user: \"Run Lighthouse audits through the PageSpeed API\""),
        )
        .arg(
            Arg::new("note")
                .long("note")
                .help("Shown to the user, like where to get the key: https://github.com/settings/tokens"),
        )
}

fn vault_oauth_app() -> Command {
    Command::new("oauth")
        .about("Sign in on the provider's web page and keep a key that renews itself. Asks in a terminal, so a human must run it")
        .arg(key_name_arg())
        .arg(host_arg().required(false).help(
            "Host the key may be sent to, e.g. gmail.googleapis.com (repeatable; signing in again keeps the current ones)",
        ))
        .arg(query_param_arg())
        .arg(method_arg())
        .arg(path_arg())
        .arg(confirm_arg())
        .arg(Arg::new("auth-url").long("auth-url").help("The provider's sign-in page, e.g. https://accounts.google.com/o/oauth2/v2/auth"))
        .arg(Arg::new("token-url").long("token-url").help("Where the provider hands out tokens, e.g. https://oauth2.googleapis.com/token"))
        .arg(Arg::new("client-id").long("client-id").help("Your OAuth app's client id. The client secret is asked for at a hidden prompt"))
        .arg(
            Arg::new("scope")
                .long("scope")
                .action(ArgAction::Append)
                .value_delimiter(',')
                .help("What the key may do, as the provider names it, e.g. https://www.googleapis.com/auth/gmail.send (repeatable)"),
        )
        .arg(
            Arg::new("auth-param")
                .long("auth-param")
                .action(ArgAction::Append)
                .help("Extra name=value for the sign-in page, e.g. access_type=offline (repeatable)"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_parser(clap::value_parser!(u16).range(1..))
                .help("Port the sign-in comes back to, for providers that need a fixed redirect URI (default: any free port)"),
        )
}

fn grant_app(name: &'static str, about: &'static str) -> Command {
    Command::new(name)
        .about(about)
        .arg(Arg::new("secret").required(true))
        .arg(Arg::new("command").required(true))
}

fn vault_log_app() -> Command {
    Command::new("log")
        .about("When keys were added, allowed, used or refused, by which command and from which programs (never values)")
        .arg(Arg::new("key").long("key").help("Only entries for this key"))
        .arg(Arg::new("command").long("command").help("Only entries for this command"))
        .arg(
            Arg::new("limit")
                .long("limit")
                .value_parser(clap::value_parser!(usize))
                .default_value("50")
                .help("How many entries to show, newest first"),
        )
        .arg(
            Arg::new("pretty")
                .long("pretty")
                .action(ArgAction::SetTrue)
                .help("One readable line per entry, oldest first, for a person to read (not JSON)"),
        )
        .arg(
            Arg::new("follow")
                .long("follow")
                .action(ArgAction::SetTrue)
                .help("Keep watching and show new entries as they happen, one JSON object per line (readable lines with --pretty)"),
        )
}

fn key_name_arg() -> Arg {
    Arg::new("name")
        .required(true)
        .help("Name scripts use, like github, or github/work for one of several accounts")
}

fn host_arg() -> Arg {
    Arg::new("host")
        .long("host")
        .required(true)
        .action(ArgAction::Append)
        .value_delimiter(',')
        .help("Host the secret may be sent to, e.g. api.github.com or 127.0.0.1:8080 (repeatable)")
}

fn query_param_arg() -> Arg {
    Arg::new("query-param")
        .long("query-param")
        .action(ArgAction::Append)
        .value_delimiter(',')
        .help("Query parameter it may also be sent in, e.g. key for ?key=... (repeatable)")
}

fn method_arg() -> Arg {
    Arg::new("method")
        .long("method")
        .action(ArgAction::Append)
        .value_delimiter(',')
        .help("Only send it with these HTTP methods, e.g. GET,HEAD (default: any)")
}

fn path_arg() -> Arg {
    Arg::new("path")
        .long("path")
        .action(ArgAction::Append)
        .value_delimiter(',')
        .help("Only send it to URL paths under these, e.g. /repos/acme (default: any)")
}

fn confirm_arg() -> Arg {
    Arg::new("confirm")
        .long("confirm")
        .action(ArgAction::Append)
        .value_delimiter(',')
        .help("Ask for Touch ID before each request with it: all, writes (anything but GET, HEAD and OPTIONS), or methods like POST,DELETE")
}
