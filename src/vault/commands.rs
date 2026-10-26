use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use anyhow::{Result, anyhow, bail, ensure};

use super::hosts::{normalize_host, normalize_query_param};
use super::log::{AuditLog, Event};
use super::names::{self, NAME_RULES, is_secret_name};
use super::scope::{self, normalize_confirm, normalize_method, normalize_path};
use super::{SecretEntry, SecretSummary, SecretValue, VaultStore, approval};
use crate::command::registry::{CommandDef, Registry};

const MAX_VIEWS: usize = 10;

pub trait Terminal {
    fn read_secret(&self, prompt: &str) -> Result<String>;
    fn ask(&self, prompt: &str) -> Result<String>;
    fn show(&self, text: &str) -> Result<()>;
    fn confirm(&self, prompt: &str) -> Result<bool>;
    fn review(&self, summary: &str, full: &str, question: &str) -> Result<bool>;
}

pub struct Tty;

impl Terminal for Tty {
    fn read_secret(&self, prompt: &str) -> Result<String> {
        rpassword::prompt_password(prompt).map_err(no_tty)
    }

    fn ask(&self, prompt: &str) -> Result<String> {
        ask(&open_tty()?, prompt)
    }

    fn show(&self, text: &str) -> Result<()> {
        writeln!(open_tty()?, "{text}")?;
        Ok(())
    }

    fn confirm(&self, prompt: &str) -> Result<bool> {
        let tty = open_tty()?;
        Ok(matches!(ask(&tty, &format!("{prompt} [y/N] "))?.as_str(), "y" | "Y" | "yes"))
    }

    fn review(&self, summary: &str, full: &str, question: &str) -> Result<bool> {
        let mut tty = open_tty()?;
        writeln!(tty, "{summary}\n")?;
        for _ in 0..MAX_VIEWS {
            match ask(&tty, &format!("{question} [y/N, v = read the whole script] "))?.as_str() {
                "v" | "V" => page(&tty, full)?,
                "y" | "Y" | "yes" => return Ok(true),
                _ => return Ok(false),
            }
        }
        writeln!(tty, "No answer after reading it {MAX_VIEWS} times, so no.")?;
        Ok(false)
    }
}

fn open_tty() -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(no_tty)
}

fn ask(mut tty: &File, prompt: &str) -> Result<String> {
    write!(tty, "{prompt}")?;
    tty.flush()?;
    let mut answer = String::new();
    BufReader::new(tty).read_line(&mut answer)?;
    Ok(answer.trim().to_string())
}

fn page(mut tty: &File, text: &str) -> Result<()> {
    let spawned = Command::new("/usr/bin/less")
        .stdin(Stdio::piped())
        .stdout(tty.try_clone()?)
        .spawn();
    let Ok(mut less) = spawned else {
        tty.write_all(text.as_bytes())?;
        return Ok(());
    };
    if let Some(mut input) = less.stdin.take() {
        let _ = input.write_all(text.as_bytes());
    }
    less.wait()?;
    Ok(())
}

#[expect(clippy::needless_pass_by_value, reason = "made for `map_err`, which passes the error by value")]
fn no_tty(err: io::Error) -> anyhow::Error {
    anyhow!(
        "this needs a human at an interactive terminal ({err}). Ask the user to run the command themselves in a terminal window"
    )
}

#[derive(Clone, Copy)]
pub struct Rules<'a> {
    pub hosts: &'a [String],
    pub query_params: &'a [String],
    pub methods: &'a [String],
    pub paths: &'a [String],
    pub confirm: &'a [String],
}

#[derive(Debug, Clone, PartialEq)]
pub struct CheckedRules {
    pub hosts: Vec<String>,
    pub query_params: Vec<String>,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    pub confirm: Vec<String>,
}

impl Rules<'_> {
    pub fn check(&self) -> Result<CheckedRules> {
        ensure!(!self.hosts.is_empty(), "give at least one --host the secret may be sent to");
        Ok(CheckedRules {
            hosts: sorted(self.hosts, normalize_host)?,
            query_params: sorted(self.query_params, normalize_query_param)?,
            methods: sorted(self.methods, normalize_method)?,
            paths: sorted(self.paths, normalize_path)?,
            confirm: normalize_confirm(self.confirm)?,
        })
    }
}

pub(super) fn sorted(items: &[String], check: fn(&str) -> Result<String>) -> Result<Vec<String>> {
    let unique: BTreeSet<String> = items.iter().map(|item| check(item)).collect::<Result<_>>()?;
    Ok(unique.into_iter().collect())
}

impl CheckedRules {
    pub fn entry(self, value: SecretValue, commands: std::collections::BTreeMap<String, String>) -> SecretEntry {
        SecretEntry {
            query_params: self.query_params,
            methods: self.methods,
            paths: self.paths,
            confirm: self.confirm,
            commands,
            ..SecretEntry::new(value, self.hosts)
        }
    }
}

pub fn add(
    store: &dyn VaultStore,
    log: &dyn AuditLog,
    term: &dyn Terminal,
    registry: &Registry,
    name: &str,
    rules: Rules,
) -> Result<SecretSummary> {
    ensure!(is_secret_name(name), "{name:?} is not a valid secret name ({NAME_RULES})");
    let checked = rules.check()?;
    let vault = store.load()?;
    let existing = vault.get(name);
    let prompt = match existing {
        Some(current) if current.oauth.is_some() => format!(
            "New value for {name} (input is hidden, leave empty to keep the current sign-in; a value replaces the sign-in with a plain key): "
        ),
        Some(_) => format!("New value for {name} (input is hidden, leave empty to keep the current one): "),
        None => format!("Value for {name} (input is hidden): "),
    };
    let typed = term.read_secret(&prompt)?;
    let new_value = !typed.trim().is_empty() || existing.is_none();
    let value = match (typed.trim(), existing) {
        ("", Some(current)) => current.value.clone(),
        (typed, _) => SecretValue::new(typed.to_string())?,
    };
    let kept_sign_in = existing.filter(|_| !new_value).and_then(|current| current.oauth.clone());
    let commands = existing.map(|current| current.commands.clone()).unwrap_or_default();
    let entry = SecretEntry { oauth: kept_sign_in, ..checked.entry(value, commands) };
    store.save(&vault.with_secret(name, entry.clone()), &add_change(name, existing, &entry, new_value))?;
    log.record(Event::added(name, &entry, new_value));
    Ok(entry.summary(name, registry))
}

fn add_change(name: &str, existing: Option<&SecretEntry>, entry: &SecretEntry, new_value: bool) -> String {
    let Some(old) = existing else {
        return format!("add the API key {name} for {}", destination(entry));
    };
    let action = if new_value {
        format!("replace the API key {name}")
    } else {
        format!("change where your API key {name} may go")
    };
    let (now, was) = (destination(entry), destination(old));
    if now == was {
        format!("{action}: still {now}")
    } else {
        format!("{action}: now {now}, was {was}")
    }
}

pub fn list(store: &dyn VaultStore, registry: &Registry) -> Result<Vec<SecretSummary>> {
    Ok(store.load()?.summaries(registry))
}

pub(super) fn destination(entry: &SecretEntry) -> String {
    let limits: Vec<String> = [
        (!entry.query_params.is_empty()).then(|| format!("also as query parameter {}", entry.query_params.join(", "))),
        (!entry.methods.is_empty()).then(|| format!("{} only", entry.methods.join(", "))),
        (!entry.paths.is_empty()).then(|| format!("paths under {}", entry.paths.join(", "))),
        confirm_text(&entry.confirm),
    ]
    .into_iter()
    .flatten()
    .collect();
    match limits.as_slice() {
        [] => entry.hosts.join(", "),
        limits => format!("{} ({})", entry.hosts.join(", "), limits.join("; ")),
    }
}

fn confirm_text(confirm: &[String]) -> Option<String> {
    let shown: Vec<&str> = confirm
        .iter()
        .map(|rule| if rule == scope::WRITES { "write (not GET, HEAD or OPTIONS)" } else { rule.as_str() })
        .collect();
    match shown.as_slice() {
        [] => None,
        [all] if *all == scope::ALL => Some("Touch ID before each use".to_string()),
        rules => Some(format!("Touch ID before each {}", rules.join(", "))),
    }
}

pub(super) fn add_flags(entry: &SecretEntry) -> String {
    let flag = |name: &str, values: &[String]| match values {
        [] => String::new(),
        values => format!(" --{name} {}", values.join(",")),
    };
    format!(
        "--host {}{}{}{}{}",
        entry.hosts.join(","),
        flag("query-param", &entry.query_params),
        flag("method", &entry.methods),
        flag("path", &entry.paths),
        flag("confirm", &entry.confirm)
    )
}

pub fn allow(
    store: &dyn VaultStore,
    log: &dyn AuditLog,
    term: &dyn Terminal,
    registry: &Registry,
    secret: &str,
    command: &str,
) -> Result<bool> {
    let vault = store.load()?;
    let entry = vault
        .get(secret)
        .ok_or_else(|| anyhow!("no secret named {secret:?}"))?;
    let def = find_command(registry, command)?;
    ensure!(
        names::declared(&def.manifest.permissions.vault, secret),
        "command {command:?} does not list {secret:?} (or a pattern covering it) in permissions.vault, so it could not use it anyway"
    );
    let script = def.read_script()?;
    let fingerprint = approval::fingerprint(&def.manifest_source, &script);
    let (key, name) = (secret.to_string(), command.to_string());
    let review = approval::review(def, &script, &[(secret, entry)]);
    if !term.review(&review.summary, &review.full, &review.question)? {
        log.record(Event::Declined { key, command: name });
        return Ok(false);
    }
    let change = format!("let the command {command} use the API key {secret}");
    store.save(&vault.with_secret(secret, entry.with_command(command, fingerprint)), &change)?;
    log.record(Event::Allowed { key, command: name });
    Ok(true)
}

pub(super) fn find_command<'r>(registry: &'r Registry, name: &str) -> Result<&'r CommandDef> {
    if let Some(def) = registry.find(name) {
        return Ok(def);
    }
    match registry.problems.iter().find(|p| p.command == name) {
        Some(broken) => bail!(
            "command {name:?} is broken ({}). Fix it first: `tb self check`",
            broken.problem
        ),
        None => bail!("no command named {name:?}"),
    }
}

pub fn revoke(
    store: &dyn VaultStore,
    log: &dyn AuditLog,
    term: &dyn Terminal,
    secret: &str,
    command: &str,
) -> Result<bool> {
    let vault = store.load()?;
    let entry = vault
        .get(secret)
        .ok_or_else(|| anyhow!("no secret named {secret:?}"))?;
    ensure!(
        entry.commands.contains_key(command),
        "command {command:?} is not allowed to use {secret:?}"
    );
    if !term.confirm(&format!("Stop {command:?} from using secret {secret:?}?"))? {
        return Ok(false);
    }
    let change = format!("stop the command {command} from using the API key {secret}");
    store.save(&vault.with_secret(secret, entry.without_command(command)), &change)?;
    log.record(Event::Revoked { key: secret.to_string(), command: command.to_string() });
    Ok(true)
}

pub fn remove(store: &dyn VaultStore, log: &dyn AuditLog, term: &dyn Terminal, name: &str) -> Result<bool> {
    let vault = store.load()?;
    ensure!(vault.get(name).is_some(), "no secret named {name:?}");
    if !term.confirm(&format!("Delete secret {name:?}?"))? {
        return Ok(false);
    }
    store.save(&vault.without_secret(name), &format!("delete the API key {name}"))?;
    log.record(Event::Removed { key: name.to_string() });
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;
    use std::path::Path;

    use super::*;
    use crate::command::manifest::Manifest;
    use crate::vault::VaultData;
    use crate::vault::approval::Access;
    use crate::vault::log::MemoryLog;
    use crate::vault::store::MemoryStore;

    struct FakeTerminal {
        secret: &'static str,
        confirm: bool,
        prompts: RefCell<Vec<String>>,
    }

    impl FakeTerminal {
        fn new(secret: &'static str, confirm: bool) -> Self {
            Self {
                secret,
                confirm,
                prompts: RefCell::new(Vec::new()),
            }
        }
    }

    impl Terminal for FakeTerminal {
        fn read_secret(&self, prompt: &str) -> Result<String> {
            self.prompts.borrow_mut().push(prompt.to_string());
            Ok(self.secret.to_string())
        }
        fn ask(&self, prompt: &str) -> Result<String> {
            self.prompts.borrow_mut().push(prompt.to_string());
            Ok(String::new())
        }
        fn show(&self, text: &str) -> Result<()> {
            self.prompts.borrow_mut().push(text.to_string());
            Ok(())
        }
        fn confirm(&self, prompt: &str) -> Result<bool> {
            self.prompts.borrow_mut().push(prompt.to_string());
            Ok(self.confirm)
        }
        fn review(&self, summary: &str, full: &str, question: &str) -> Result<bool> {
            self.prompts.borrow_mut().push(format!("{summary}\n{full}\n{question}"));
            Ok(self.confirm)
        }
    }

    fn term() -> FakeTerminal {
        FakeTerminal::new("  fake_stripe_0123456789\n", true)
    }

    fn rules<'a>(hosts: &'a [String], query_params: &'a [String]) -> Rules<'a> {
        Rules { hosts, query_params, methods: &[], paths: &[], confirm: &[] }
    }

    fn add_simple(store: &MemoryStore, term: &FakeTerminal, hosts: &[&str]) -> Result<SecretSummary> {
        let hosts: Vec<String> = hosts.iter().map(std::string::ToString::to_string).collect();
        add(store, &*MemoryLog::new(), term, &Registry::default(), "stripe", rules(&hosts, &[]))
    }

    fn command(root: &Path, name: &str, vault: &[&str]) -> CommandDef {
        let dir = root.join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("run.lua"), "return function() end").unwrap();
        let source = serde_json::json!({
            "name": name,
            "description": "test",
            "permissions": { "http": ["api.stripe.com"], "vault": vault },
        })
        .to_string();
        CommandDef {
            manifest: Manifest::parse(&source).unwrap(),
            manifest_source: source,
            dir,
        }
    }

    #[test]
    fn add_stores_trimmed_value_and_normalized_rules() {
        let store = MemoryStore::new(VaultData::default());
        let hosts = vec!["API.Stripe.com".to_string(), "127.0.0.1:8080".to_string()];
        let params = vec!["key".to_string()];
        let summary = add(&store, &*MemoryLog::new(), &term(), &Registry::default(), "stripe", rules(&hosts, &params)).unwrap();
        assert_eq!(summary.hosts, vec!["127.0.0.1:8080", "api.stripe.com"]);
        assert_eq!(summary.query_params, vec!["key"]);
        let saved = store.load().unwrap();
        assert_eq!(saved.get("stripe").unwrap().value.expose(), "fake_stripe_0123456789");
    }

    #[test]
    fn add_validates_input() {
        let store = MemoryStore::new(VaultData::default());
        let ok = vec!["x.com".to_string()];
        let none = Registry::default();
        assert!(add(&store, &*MemoryLog::new(), &term(), &none, "Bad Name", rules(&ok, &[])).is_err());
        assert!(add(&store, &*MemoryLog::new(), &term(), &none, "ok", rules(&[], &[])).is_err());
        assert!(add_simple(&store, &term(), &["https://x.com"]).is_err());
        assert!(add_simple(&store, &term(), &["localhost"]).is_err());
        assert!(add(&store, &*MemoryLog::new(), &term(), &none, "ok", rules(&ok, &["a b".to_string()])).is_err());
        let short = FakeTerminal::new("abc", true);
        assert!(add_simple(&store, &short, &["x.com"]).is_err());
        let empty = FakeTerminal::new("", true);
        assert!(add_simple(&store, &empty, &["x.com"]).is_err());
        assert!(store.load().unwrap().secrets.is_empty());
    }

    #[test]
    fn adding_again_with_an_empty_value_keeps_key_and_approvals() {
        let store = MemoryStore::new(VaultData::default());
        add_simple(&store, &term(), &["api.stripe.com"]).unwrap();
        let entry = store.load().unwrap().get("stripe").unwrap().with_command("charge", "fp".into());
        store.save(&store.load().unwrap().with_secret("stripe", entry), "test").unwrap();

        let keep = FakeTerminal::new("", true);
        let summary = add_simple(&store, &keep, &["api.stripe.com", "files.stripe.com"]).unwrap();
        assert_eq!(summary.hosts, vec!["api.stripe.com", "files.stripe.com"]);
        assert!(keep.prompts.borrow()[0].contains("leave empty to keep"));
        let saved = store.load().unwrap();
        let stripe = saved.get("stripe").unwrap();
        assert_eq!(stripe.value.expose(), "fake_stripe_0123456789");
        assert_eq!(stripe.commands.get("charge").map(String::as_str), Some("fp"));
    }

    #[test]
    fn list_never_includes_values() {
        let store = MemoryStore::new(VaultData::default());
        add_simple(&store, &term(), &["api.stripe.com"]).unwrap();
        let json = serde_json::to_string(&list(&store, &Registry::default()).unwrap()).unwrap();
        assert!(!json.contains("fake_stripe"));
        assert!(json.contains("stripe"));
    }

    #[test]
    fn allow_pins_the_command_and_shows_its_script() {
        let tmp = tempfile::tempdir().unwrap();
        let store = MemoryStore::new(VaultData::default());
        add_simple(&store, &term(), &["api.stripe.com"]).unwrap();
        let registry = Registry {
            commands: vec![command(tmp.path(), "charge", &["stripe"])],
            problems: vec![],
        };

        let decline = FakeTerminal::new("", false);
        assert!(!allow(&store, &*MemoryLog::new(), &decline, &registry, "stripe", "charge").unwrap());
        assert!(decline.prompts.borrow()[0].contains("return function() end"));
        assert!(store.load().unwrap().get("stripe").unwrap().commands.is_empty());

        assert!(allow(&store, &*MemoryLog::new(), &term(), &registry, "stripe", "charge").unwrap());
        let listed = list(&store, &registry).unwrap();
        assert_eq!(listed[0].commands[0].access, Access::Allowed);

        fs::write(tmp.path().join("charge/run.lua"), "return function() return 1 end").unwrap();
        let listed = list(&store, &registry).unwrap();
        assert_eq!(listed[0].commands[0].access, Access::Changed);
    }

    #[test]
    fn keys_in_a_folder_are_allowed_one_by_one() {
        let tmp = tempfile::tempdir().unwrap();
        let store = MemoryStore::new(VaultData::default());
        let hosts = vec!["api.stripe.com".to_string()];
        let none = Registry::default();
        for name in ["stripe/live", "stripe/test"] {
            add(&store, &*MemoryLog::new(), &term(), &none, name, rules(&hosts, &[])).unwrap();
        }
        let err = add(&store, &*MemoryLog::new(), &term(), &none, "stripe/a/b/c", rules(&hosts, &[]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("1-3 parts"), "{err}");

        let registry = Registry { commands: vec![command(tmp.path(), "charge", &["stripe/*"])], problems: vec![] };
        assert!(allow(&store, &*MemoryLog::new(), &term(), &registry, "stripe/live", "charge").unwrap());
        let listed = list(&store, &registry).unwrap();
        let access: Vec<(&str, Access)> = listed.iter().map(|s| (s.name.as_str(), s.commands[0].access)).collect();
        assert_eq!(access, vec![("stripe/live", Access::Allowed), ("stripe/test", Access::NotAllowed)]);

        for uncovered in ["stripe", "stripe/live/eu"] {
            add(&store, &*MemoryLog::new(), &term(), &none, uncovered, rules(&hosts, &[])).unwrap();
            let err = allow(&store, &*MemoryLog::new(), &term(), &registry, uncovered, "charge").unwrap_err();
            assert!(err.to_string().contains("does not list"), "{uncovered}: {err}");
        }
    }

    #[test]
    fn allow_refuses_unknown_broken_or_undeclaring_commands() {
        let tmp = tempfile::tempdir().unwrap();
        let store = MemoryStore::new(VaultData::default());
        add_simple(&store, &term(), &["api.stripe.com"]).unwrap();
        let registry = Registry {
            commands: vec![command(tmp.path(), "other", &[])],
            problems: vec![crate::command::registry::Problem {
                command: "broken".into(),
                problem: "missing run.lua".into(),
            }],
        };
        let err = |secret, cmd| allow(&store, &*MemoryLog::new(), &term(), &registry, secret, cmd).unwrap_err().to_string();
        assert!(err("stripe", "nope").contains("no command named"));
        assert!(err("stripe", "broken").contains("missing run.lua"));
        assert!(err("stripe", "other").contains("does not list"));
        assert!(err("github", "other").contains("no secret named"));
    }

    #[test]
    fn revoke_respects_confirmation() {
        let store = MemoryStore::new(VaultData::default());
        add_simple(&store, &term(), &["api.stripe.com"]).unwrap();
        let entry = store.load().unwrap().get("stripe").unwrap().with_command("charge", "fp".into());
        store.save(&store.load().unwrap().with_secret("stripe", entry), "test").unwrap();

        let decline = FakeTerminal::new("", false);
        assert!(!revoke(&store, &*MemoryLog::new(), &decline, "stripe", "charge").unwrap());
        assert!(revoke(&store, &*MemoryLog::new(), &term(), "stripe", "charge").unwrap());
        assert!(store.load().unwrap().get("stripe").unwrap().commands.is_empty());
        assert!(revoke(&store, &*MemoryLog::new(), &term(), "stripe", "charge").is_err());
    }

    #[test]
    fn remove_respects_confirmation() {
        let store = MemoryStore::new(VaultData::default());
        add_simple(&store, &term(), &["api.stripe.com"]).unwrap();

        let decline = FakeTerminal::new("", false);
        assert!(!remove(&store, &*MemoryLog::new(), &decline, "stripe").unwrap());
        assert!(store.load().unwrap().get("stripe").is_some());

        assert!(remove(&store, &*MemoryLog::new(), &term(), "stripe").unwrap());
        assert!(store.load().unwrap().get("stripe").is_none());
        assert!(remove(&store, &*MemoryLog::new(), &term(), "stripe").is_err());
    }

    #[test]
    fn add_keeps_method_path_and_confirm_rules() {
        let store = MemoryStore::new(VaultData::default());
        let hosts = vec!["api.github.com".to_string()];
        let (methods, paths) = (vec!["get".to_string(), "HEAD".to_string()], vec!["/repos/acme/".to_string()]);
        let confirm = vec!["writes".to_string()];
        let narrow = Rules { hosts: &hosts, query_params: &[], methods: &methods, paths: &paths, confirm: &confirm };
        let summary = add(&store, &*MemoryLog::new(), &term(), &Registry::default(), "github", narrow).unwrap();
        assert_eq!((summary.methods, summary.paths, summary.confirm), (
            vec!["GET".to_string(), "HEAD".to_string()],
            vec!["/repos/acme".to_string()],
            vec!["writes".to_string()]
        ));
        assert_eq!(
            store.changes.borrow()[0],
            "add the API key github for api.github.com (GET, HEAD only; paths under /repos/acme; Touch ID before each write (not GET, HEAD or OPTIONS))"
        );
        let saved = store.load().unwrap();
        assert_eq!(add_flags(saved.get("github").unwrap()), "--host api.github.com --method GET,HEAD --path /repos/acme --confirm writes");

        for (bad_methods, bad_paths, bad_confirm) in [(vec!["G T"], vec![], vec![]), (vec![], vec!["repos"], vec![]), (vec![], vec![], vec!["PSOT"])] {
            let strings = |items: Vec<&str>| items.into_iter().map(String::from).collect::<Vec<_>>();
            let (m, p, c) = (strings(bad_methods), strings(bad_paths), strings(bad_confirm));
            let rules = Rules { hosts: &hosts, query_params: &[], methods: &m, paths: &p, confirm: &c };
            assert!(add(&store, &*MemoryLog::new(), &term(), &Registry::default(), "github", rules).is_err());
        }
        assert_eq!(store.changes.borrow().len(), 1, "a bad rule changes nothing");
    }

    #[test]
    fn changing_rules_keeps_a_sign_in_but_a_new_value_replaces_it() {
        let store = MemoryStore::new(VaultData::default());
        add_simple(&store, &term(), &["api.example.com"]).unwrap();
        let oauth = crate::vault::oauth::OAuth {
            auth_url: "https://accounts.example.com/auth".into(),
            token_url: "https://accounts.example.com/token".into(),
            client_id: "fake-client".into(),
            client_secret: None,
            scopes: vec![],
            auth_params: std::collections::BTreeMap::new(),
            port: None,
            cache_key: crate::vault::oauth::new_cache_key().unwrap(),
        };
        let signed = SecretEntry { oauth: Some(oauth), ..store.load().unwrap().get("stripe").unwrap().clone() };
        store.save(&store.load().unwrap().with_secret("stripe", signed), "test").unwrap();

        let keep = FakeTerminal::new("", true);
        add_simple(&store, &keep, &["api.example.com", "files.example.com"]).unwrap();
        assert!(keep.prompts.borrow()[0].contains("keep the current sign-in"), "{:?}", keep.prompts.borrow());
        assert!(store.load().unwrap().get("stripe").unwrap().oauth.is_some());

        add_simple(&store, &term(), &["api.example.com"]).unwrap();
        assert!(store.load().unwrap().get("stripe").unwrap().oauth.is_none());
    }

    #[test]
    fn every_change_says_what_the_person_approves() {
        let tmp = tempfile::tempdir().unwrap();
        let store = MemoryStore::new(VaultData::default());
        let hosts = vec!["api.stripe.com".to_string(), "files.stripe.com".to_string()];
        let evil = vec!["evil.example".to_string()];
        let none = Registry::default();
        add(&store, &*MemoryLog::new(), &term(), &none, "stripe", rules(&hosts, &[])).unwrap();
        let keep = FakeTerminal::new("", true);
        add(&store, &*MemoryLog::new(), &keep, &none, "stripe", rules(&evil, &[])).unwrap();
        add(&store, &*MemoryLog::new(), &term(), &none, "stripe", rules(&evil, &["key".to_string()])).unwrap();
        let registry = Registry { commands: vec![command(tmp.path(), "charge", &["stripe"])], problems: vec![] };
        allow(&store, &*MemoryLog::new(), &term(), &registry, "stripe", "charge").unwrap();
        revoke(&store, &*MemoryLog::new(), &term(), "stripe", "charge").unwrap();
        remove(&store, &*MemoryLog::new(), &term(), "stripe").unwrap();
        assert_eq!(
            *store.changes.borrow(),
            vec![
                "add the API key stripe for api.stripe.com, files.stripe.com",
                "change where your API key stripe may go: now evil.example, was api.stripe.com, files.stripe.com",
                "replace the API key stripe: now evil.example (also as query parameter key), was evil.example",
                "let the command charge use the API key stripe",
                "stop the command charge from using the API key stripe",
                "delete the API key stripe",
            ]
        );
    }

    #[test]
    fn every_change_is_logged_without_the_value() {
        let tmp = tempfile::tempdir().unwrap();
        let store = MemoryStore::new(VaultData::default());
        let log = MemoryLog::new();
        let hosts = vec!["api.stripe.com".to_string()];
        add(&store, &log, &term(), &Registry::default(), "stripe", rules(&hosts, &[])).unwrap();
        add(&store, &log, &FakeTerminal::new("", true), &Registry::default(), "stripe", rules(&hosts, &[])).unwrap();
        let registry = Registry { commands: vec![command(tmp.path(), "charge", &["stripe"])], problems: vec![] };
        allow(&store, &log, &FakeTerminal::new("", false), &registry, "stripe", "charge").unwrap();
        allow(&store, &log, &term(), &registry, "stripe", "charge").unwrap();
        revoke(&store, &log, &term(), "stripe", "charge").unwrap();
        remove(&store, &log, &term(), "stripe").unwrap();

        let events = log.0.borrow();
        let (key, command) = ("stripe".to_string(), "charge".to_string());
        assert!(matches!(&events[0], Event::Added { new_value: true, .. }), "{events:?}");
        assert!(matches!(&events[1], Event::Added { new_value: false, .. }), "{events:?}");
        assert_eq!(events[2], Event::Declined { key: key.clone(), command: command.clone() });
        assert_eq!(events[3], Event::Allowed { key: key.clone(), command: command.clone() });
        assert_eq!(events[4], Event::Revoked { key: key.clone(), command });
        assert_eq!(events[5], Event::Removed { key });
        assert_eq!(events.len(), 6);
        assert!(!format!("{events:?}").contains("fake_stripe"));
    }
}
