//! `tb self vault setup`: everything waiting for the human, in one go. Keys an agent
//! requested get their value, commands that need a key get reviewed, and the whole
//! batch is saved at once, so the Keychain asks for Touch ID only once.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Result, bail};
use serde::Serialize;

use super::approval::{self, fingerprint};
use super::commands::{Terminal, destination, find_command};
use super::hosts::{local_note, normalize_host, normalize_query_param};
use super::log::{AuditLog, Event};
use super::names::{self, is_secret_name};
use super::requests::{self, KeyRequest};
use super::{SecretEntry, SecretValue, VaultData, VaultStore};
use crate::registry::{CommandDef, Registry};
use crate::screen::{one_line, printable};

/// Wrong answers allowed at one prompt before setup stops without changing anything.
const MAX_TRIES: usize = 3;

/// What `tb self vault setup` prints when it's done.
#[derive(Debug, Default, PartialEq, Serialize)]
pub struct Report {
    pub added: Vec<String>,
    pub allowed: Vec<Grant>,
    pub declined: Vec<Grant>,
    /// Keys left for later. Their requests stay.
    pub skipped: Vec<String>,
    /// Entries of the requests file left out: broken, repeated or past the limit.
    #[serde(skip_serializing_if = "is_zero")]
    pub ignored_requests: usize,
}

fn is_zero(count: &usize) -> bool {
    *count == 0
}

impl Report {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Grant {
    pub key: String,
    pub command: String,
}

/// A key to ask the human for: one an agent requested, or one a named command
/// lists that nobody requested.
struct NewKey {
    request: KeyRequest,
    requested: bool,
    /// Hosts the command calls, shown when there are too many to pick one.
    calls: Vec<String>,
}

/// A command's answer for one key, with the fingerprint of the files the human saw.
struct Decision {
    grant: Grant,
    fingerprint: String,
    allowed: bool,
}

/// Adds the requested keys and reviews every command waiting for a key, or only
/// `only`. Nothing is saved until the end, so stopping halfway changes nothing.
pub fn setup(
    store: &dyn VaultStore,
    log: &dyn AuditLog,
    term: &dyn Terminal,
    registry: &Registry,
    requests_path: &Path,
    only: Option<&str>,
) -> Result<Report> {
    let only = only.map(|name| find_command(registry, name)).transpose()?;
    let vault = store.load()?;
    let requests::Waiting { requests: waiting, ignored } = requests::load(requests_path)?;

    let answered = keys_to_add(&vault, &waiting, only)
        .into_iter()
        .map(|key| Ok((ask_new_key(term, registry, &key)?, key.request.name)))
        .collect::<Result<Vec<_>>>()?;
    let added: Vec<(String, SecretEntry)> = answered
        .iter()
        .filter_map(|(entry, name)| entry.clone().map(|entry| (name.clone(), entry)))
        .collect();
    let skipped: Vec<String> = answered
        .iter()
        .filter(|(entry, _)| entry.is_none())
        .map(|(_, name)| name.clone())
        .collect();
    let with_keys = added
        .iter()
        .fold(vault, |data, (name, entry)| data.with_secret(name, entry.clone()));

    let new_names: BTreeSet<&str> = added.iter().map(|(name, _)| name.as_str()).collect();
    let commands: Vec<&CommandDef> = match only {
        Some(def) => vec![def],
        None => registry.commands.iter().collect(),
    };
    let decisions: Vec<Decision> = commands
        .into_iter()
        .map(|def| review_command(term, def, &with_keys, &new_names, only.is_some()))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    let (yes, no): (Vec<Decision>, Vec<Decision>) = decisions.into_iter().partition(|d| d.allowed);
    for declined in &no {
        log.record(Event::Declined { key: declined.grant.key.clone(), command: declined.grant.command.clone() });
    }
    let done = yes.iter().fold(with_keys, |data, d| {
        let entry = data.get(&d.grant.key).expect("reviewed keys exist").with_command(&d.grant.command, d.fingerprint.clone());
        data.with_secret(&d.grant.key, entry)
    });
    let allowed: Vec<Grant> = yes.into_iter().map(|d| d.grant).collect();

    if !added.is_empty() || !allowed.is_empty() {
        store.save(&done, &change(&added, &allowed))?;
        for (name, entry) in &added {
            log.record(Event::Added {
                key: name.clone(),
                hosts: entry.hosts.clone(),
                query_params: entry.query_params.clone(),
                new_value: true,
            });
        }
        for grant in &allowed {
            log.record(Event::Allowed { key: grant.key.clone(), command: grant.command.clone() });
        }
    }
    // The vault is saved by now: a file that can't be tidied must not hide that.
    if let Err(err) = forget_fulfilled(requests_path, &done) {
        eprintln!("toolbox: your changes are saved, but {} could not be updated: {err:#}", requests_path.display());
    }
    Ok(Report {
        added: added.into_iter().map(|(name, _)| name).collect(),
        allowed,
        declined: no.into_iter().map(|d| d.grant).collect(),
        skipped,
        ignored_requests: ignored,
    })
}

/// Requested keys not in the vault yet, and, for a named command, the keys it lists
/// by exact name that nobody requested.
fn keys_to_add(vault: &VaultData, waiting: &[KeyRequest], only: Option<&CommandDef>) -> Vec<NewKey> {
    let requested = waiting
        .iter()
        .filter(|req| vault.get(&req.name).is_none())
        .filter(|req| only.is_none_or(|def| names::declared(&def.manifest.permissions.vault, &req.name)))
        .map(|req| NewKey { request: req.clone(), requested: true, calls: Vec::new() });
    let unrequested = only.into_iter().flat_map(move |def| {
        let calls: Vec<String> = def
            .manifest
            .permissions
            .http
            .iter()
            .filter_map(|host| normalize_host(host).ok())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        def.manifest
            .permissions
            .vault
            .iter()
            .filter(move |name| is_secret_name(name) && vault.get(name).is_none())
            .filter(move |name| !waiting.iter().any(|req| &req.name == *name))
            .map(move |name| NewKey {
                // Only a command that calls one host gets it as the default.
                request: KeyRequest {
                    name: name.clone(),
                    hosts: if calls.len() == 1 { calls.clone() } else { Vec::new() },
                    query_params: Vec::new(),
                    why: String::new(),
                    note: None,
                },
                requested: false,
                calls: calls.clone(),
            })
    });
    requested.chain(unrequested).collect()
}

/// Shows what the key is for, then asks where it may go and for its value.
/// `None` when the human skips it.
fn ask_new_key(term: &dyn Terminal, registry: &Registry, key: &NewKey) -> Result<Option<SecretEntry>> {
    let req = &key.request;
    let users: Vec<&str> = registry
        .commands
        .iter()
        .filter(|def| names::declared(&def.manifest.permissions.vault, &req.name))
        .map(|def| def.manifest.name.as_str())
        .collect();
    let header = [
        Some(format!("\nKey {} {}", req.name, if key.requested { "was requested" } else { "is missing" })),
        (!req.why.is_empty()).then(|| format!("  why: {}", one_line(&req.why))),
        req.note.as_ref().map(|note| format!("  note: {}", one_line(note))),
        Some(match users.as_slice() {
            [] => "  no command uses it yet".to_string(),
            names => format!("  used by {}", names.join(", ")),
        }),
        (req.hosts.is_empty() && !key.calls.is_empty()).then(|| format!("  the command calls {}", key.calls.join(", "))),
    ];
    term.show(&printable(&header.into_iter().flatten().collect::<Vec<_>>().join("\n")))?;

    let hosts_prompt = match req.hosts.as_slice() {
        [] => "Hosts it may go to (empty skips this key): ".to_string(),
        hosts => format!("Hosts it may go to (Enter keeps {}, - skips this key): ", hosts.join(", ")),
    };
    let hosts = ask_list(term, &hosts_prompt, &req.hosts, normalize_host)?;
    if hosts.is_empty() {
        return Ok(None);
    }
    if let Some(note) = local_note(&hosts) {
        term.show(&note)?;
    }
    let query_params = match req.query_params.as_slice() {
        [] => Vec::new(),
        params => {
            let prompt = format!("Query parameters it may go in (Enter keeps {}, - for headers only): ", params.join(", "));
            ask_list(term, &prompt, params, normalize_query_param)?
        }
    };
    let Some(value) = ask_value(term, &req.name)? else {
        return Ok(None);
    };
    Ok(Some(SecretEntry { value, hosts, query_params, commands: BTreeMap::new() }))
}

/// A comma-separated list where every item passes `check`. Enter takes `default`
/// and `-` means none.
fn ask_list(term: &dyn Terminal, prompt: &str, default: &[String], check: fn(&str) -> Result<String>) -> Result<Vec<String>> {
    for _ in 0..MAX_TRIES {
        let typed = term.ask(prompt)?;
        let raw: Vec<String> = match typed.trim() {
            "" => default.to_vec(),
            "-" => Vec::new(),
            typed => typed.split(',').map(str::trim).filter(|item| !item.is_empty()).map(str::to_string).collect(),
        };
        match raw.iter().map(|item| check(item)).collect::<Result<BTreeSet<String>>>() {
            Ok(items) => return Ok(items.into_iter().collect()),
            Err(err) => term.show(&printable(&format!("  {err}")))?,
        }
    }
    bail!("stopped after {MAX_TRIES} answers that didn't work. Nothing was changed")
}

fn ask_value(term: &dyn Terminal, name: &str) -> Result<Option<SecretValue>> {
    for _ in 0..MAX_TRIES {
        let typed = term.read_secret(&format!("Paste the key for {name} (input is hidden, empty skips it): "))?;
        if typed.trim().is_empty() {
            return Ok(None);
        }
        match SecretValue::new(typed.trim().to_string()) {
            Ok(value) => return Ok(Some(value)),
            Err(err) => term.show(&format!("  {err}"))?,
        }
    }
    bail!("stopped after {MAX_TRIES} values that didn't work. Nothing was changed")
}

/// Shows the command once, then asks about each key it is waiting for: keys it
/// was allowed but changed since, keys added just now, keys it lists by exact
/// name, and, when the human named the command, keys a pattern of its covers.
fn review_command(
    term: &dyn Terminal,
    def: &CommandDef,
    vault: &VaultData,
    new_names: &BTreeSet<&str>,
    named: bool,
) -> Result<Vec<Decision>> {
    let declared = &def.manifest.permissions.vault;
    if !vault.secrets.keys().any(|key| names::declared(declared, key)) {
        return Ok(Vec::new());
    }
    // The review and the fingerprint come from the same text, so what was shown is what gets allowed.
    // In a sweep, one unreadable command must not throw away the keys already pasted.
    let script = match def.read_script() {
        Ok(script) => script,
        Err(err) if !named => {
            eprintln!("toolbox: skipped {}: {err:#}", def.manifest.name);
            return Ok(Vec::new());
        }
        Err(err) => return Err(err),
    };
    let fingerprint = fingerprint(&def.manifest_source, &script);
    let command = &def.manifest.name;
    let waiting: Vec<(&str, &SecretEntry)> = vault
        .secrets
        .iter()
        .filter(|(key, _)| names::declared(declared, key))
        .filter(|(key, entry)| match entry.commands.get(command) {
            Some(approved) => *approved != fingerprint,
            None => named || new_names.contains(key.as_str()) || declared.contains(key),
        })
        .map(|(key, entry)| (key.as_str(), entry))
        .collect();
    let Some(((first, _), rest)) = waiting.split_first() else {
        return Ok(Vec::new());
    };
    let review = approval::review(def, &script, &waiting);
    term.show("")?;
    let first_answer = term.review(&review.summary, &review.full, &review.question)?;
    let answers = rest
        .iter()
        .map(|(key, _)| term.confirm(&printable(&format!("Allow {command} to use {key} too?"))))
        .collect::<Result<Vec<bool>>>()?;
    let keys = std::iter::once(*first).chain(rest.iter().map(|(key, _)| *key));
    Ok(keys
        .zip(std::iter::once(first_answer).chain(answers))
        .map(|(key, allowed)| Decision {
            grant: Grant { key: key.to_string(), command: command.clone() },
            fingerprint: fingerprint.clone(),
            allowed,
        })
        .collect())
}

/// The Touch ID sentence: every key added and every command allowed, in one line.
/// Commands getting a key you already had come first: with a faked terminal this
/// sentence is all the person reads, and a long list of new keys must not push the
/// one that matters out of sight.
fn change(added: &[(String, SecretEntry)], allowed: &[Grant]) -> String {
    let is_new = |grant: &&Grant| added.iter().any(|(name, _)| *name == grant.key);
    let (to_new, to_old): (Vec<&Grant>, Vec<&Grant>) = allowed.iter().partition(is_new);
    let adds = added
        .iter()
        .map(|(name, entry)| format!("add the API key {name} for {}", destination(entry)));
    lets(&to_old).into_iter().chain(adds).chain(lets(&to_new)).collect::<Vec<_>>().join("; ")
}

/// One "let the command ... use ..." per command, in order of name.
fn lets(grants: &[&Grant]) -> Vec<String> {
    let commands: BTreeSet<&str> = grants.iter().map(|grant| grant.command.as_str()).collect();
    commands
        .into_iter()
        .map(|command| {
            let keys: Vec<&str> = grants
                .iter()
                .filter(|grant| grant.command == command)
                .map(|grant| grant.key.as_str())
                .collect();
            let plural = if keys.len() > 1 { "s" } else { "" };
            format!("let the command {command} use the API key{plural} {}", keys.join(", "))
        })
        .collect()
}

/// Drops requests whose key is in the vault now, however it got there, and
/// entries `load` left out. Read again, so a request filed meanwhile stays.
fn forget_fulfilled(path: &Path, vault: &VaultData) -> Result<()> {
    let now = requests::load(path)?;
    let remaining: Vec<KeyRequest> = now
        .requests
        .iter()
        .filter(|req| vault.get(&req.name).is_none())
        .cloned()
        .collect();
    if remaining.len() == now.requests.len() && now.ignored == 0 {
        return Ok(());
    }
    requests::save(path, &remaining)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs;

    use anyhow::anyhow;

    use super::*;
    use crate::manifest::Manifest;
    use crate::vault::approval::Access;
    use crate::vault::log::MemoryLog;
    use crate::vault::requests::{REQUESTS_FILE, with_request};
    use crate::vault::store::MemoryStore;

    const VALUE: &str = "fake_maps_0123456789";

    /// Answers prompts in order and fails when it runs out, like a human who stopped.
    struct Script {
        answers: RefCell<VecDeque<&'static str>>,
        seen: RefCell<Vec<String>>,
    }

    impl Script {
        fn new(answers: &[&'static str]) -> Self {
            Self { answers: RefCell::new(answers.iter().copied().collect()), seen: RefCell::new(Vec::new()) }
        }

        fn next(&self, prompt: &str) -> Result<String> {
            self.seen.borrow_mut().push(prompt.to_string());
            let answer = self.answers.borrow_mut().pop_front();
            answer.map(str::to_string).ok_or_else(|| anyhow!("no answer left for {prompt:?}"))
        }

        fn saw(&self, text: &str) -> bool {
            self.seen.borrow().iter().any(|seen| seen.contains(text))
        }
    }

    impl Terminal for Script {
        fn read_secret(&self, prompt: &str) -> Result<String> {
            self.next(prompt)
        }
        fn ask(&self, prompt: &str) -> Result<String> {
            self.next(prompt)
        }
        fn show(&self, text: &str) -> Result<()> {
            self.seen.borrow_mut().push(text.to_string());
            Ok(())
        }
        fn confirm(&self, prompt: &str) -> Result<bool> {
            Ok(self.next(prompt)? == "y")
        }
        fn review(&self, summary: &str, _full: &str, question: &str) -> Result<bool> {
            self.seen.borrow_mut().push(summary.to_string());
            Ok(self.next(question)? == "y")
        }
    }

    struct Home {
        dir: tempfile::TempDir,
        store: MemoryStore,
        log: std::rc::Rc<MemoryLog>,
        registry: Registry,
    }

    impl Home {
        fn new(commands: &[(&str, &[&str], &[&str])]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let commands = commands.iter().map(|(name, http, vault)| command(dir.path(), name, http, vault)).collect();
            Self {
                dir,
                store: MemoryStore::new(VaultData::default()),
                log: MemoryLog::new(),
                registry: Registry { commands, problems: vec![] },
            }
        }

        fn requests(&self) -> std::path::PathBuf {
            self.dir.path().join(REQUESTS_FILE)
        }

        fn request(&self, name: &str, hosts: &[&str], params: &[&str]) {
            let strings = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
            let note = Some("Get it at https://example.com");
            let req = KeyRequest::new(name, &strings(hosts), &strings(params), "Run audits", note).unwrap();
            let waiting = requests::load(&self.requests()).unwrap().requests;
            requests::save(&self.requests(), &with_request(&waiting, req)).unwrap();
        }

        fn setup(&self, term: &Script, only: Option<&str>) -> Result<Report> {
            setup(&self.store, &*self.log, term, &self.registry, &self.requests(), only)
        }

        fn access(&self, key: &str) -> Vec<(String, Access)> {
            let data = self.store.load().unwrap();
            approval::access(key, data.get(key).unwrap(), &self.registry).into_iter().map(|a| (a.name, a.access)).collect()
        }
    }

    fn command(root: &Path, name: &str, http: &[&str], vault: &[&str]) -> CommandDef {
        let dir = root.join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("run.lua"), "return function() end").unwrap();
        let source = serde_json::json!({
            "name": name,
            "description": "test",
            "permissions": { "http": http, "vault": vault },
        })
        .to_string();
        CommandDef { manifest: Manifest::parse(&source).unwrap(), manifest_source: source, dir }
    }

    fn grant(key: &str, command: &str) -> Grant {
        Grant { key: key.into(), command: command.into() }
    }

    #[test]
    fn a_requested_key_is_added_and_allowed_with_one_save() {
        let home = Home::new(&[("lighthouse", &["www.googleapis.com"], &["maps"])]);
        home.request("maps", &["www.googleapis.com"], &["key"]);
        let term = Script::new(&["", "", VALUE, "y"]);
        let report = home.setup(&term, None).unwrap();
        assert_eq!(
            report,
            Report { added: vec!["maps".into()], allowed: vec![grant("maps", "lighthouse")], ..Report::default() }
        );
        assert!(term.saw("Key maps was requested\n  why: Run audits\n  note: Get it at https://example.com\n  used by lighthouse"));
        assert!(term.saw("Hosts it may go to (Enter keeps www.googleapis.com, - skips this key): "));
        assert!(term.saw("Query parameters it may go in (Enter keeps key, - for headers only): "));
        assert!(term.saw("lighthouse wants to use your key maps"));
        assert_eq!(
            *home.store.changes.borrow(),
            vec![
                "add the API key maps for www.googleapis.com (also as query parameter key); let the command lighthouse use the API key maps"
            ]
        );
        assert_eq!(home.store.load().unwrap().get("maps").unwrap().value.expose(), VALUE);
        assert_eq!(home.access("maps"), vec![("lighthouse".into(), Access::Allowed)]);
        assert!(requests::load(&home.requests()).unwrap().requests.is_empty());
        let events = home.log.0.borrow();
        assert!(matches!(&events[0], Event::Added { key, new_value: true, .. } if key == "maps"), "{events:?}");
        assert_eq!(events[1], Event::Allowed { key: "maps".into(), command: "lighthouse".into() });
        assert!(!format!("{events:?}").contains(VALUE));
    }

    #[test]
    fn the_human_can_change_where_a_requested_key_goes() {
        let home = Home::new(&[]);
        home.request("maps", &["evil.example"], &["key"]);
        let term = Script::new(&["https://bad", "maps.googleapis.com", "-", VALUE]);
        let report = home.setup(&term, None).unwrap();
        assert_eq!(report.added, vec!["maps"]);
        assert!(term.saw("is not a valid host"));
        let data = home.store.load().unwrap();
        let maps = data.get("maps").unwrap();
        assert_eq!((maps.hosts.clone(), maps.query_params.clone()), (vec!["maps.googleapis.com".into()], vec![]));
        assert_eq!(*home.store.changes.borrow(), vec!["add the API key maps for maps.googleapis.com"]);
    }

    #[test]
    fn skipping_keeps_the_request_and_changes_nothing() {
        let home = Home::new(&[]);
        home.request("maps", &["maps.googleapis.com"], &[]);
        home.request("github", &["api.github.com"], &[]);
        let term = Script::new(&["", "", "-"]);
        let report = home.setup(&term, None).unwrap();
        assert_eq!(report.skipped, vec!["maps", "github"]);
        assert!(home.store.changes.borrow().is_empty());
        assert_eq!(requests::load(&home.requests()).unwrap().requests.len(), 2);
    }

    #[test]
    fn stopping_halfway_saves_nothing() {
        let home = Home::new(&[("lighthouse", &["www.googleapis.com"], &["maps"])]);
        home.request("maps", &["www.googleapis.com"], &[]);
        assert!(home.setup(&Script::new(&["", VALUE]), None).is_err(), "no answer at the review");
        assert!(home.setup(&Script::new(&["a b", "c d", "e f"]), None).unwrap_err().to_string().contains("Nothing was changed"));
        assert!(home.setup(&Script::new(&["", "short", "short", "short"]), None).is_err());
        assert!(home.store.changes.borrow().is_empty());
        assert_eq!(requests::load(&home.requests()).unwrap().requests.len(), 1);
    }

    #[test]
    fn changed_commands_are_reviewed_again_and_declines_are_logged() {
        let home = Home::new(&[("charge", &["api.stripe.com"], &["stripe"]), ("refund", &["api.stripe.com"], &["stripe"])]);
        home.request("stripe", &["api.stripe.com"], &[]);
        home.setup(&Script::new(&["", VALUE, "y", "y"]), None).unwrap();
        assert_eq!(home.access("stripe").iter().filter(|(_, a)| *a == Access::Allowed).count(), 2);

        fs::write(home.dir.path().join("charge/run.lua"), "return function() return 1 end").unwrap();
        let term = Script::new(&["n"]);
        let report = home.setup(&term, None).unwrap();
        assert_eq!(report.declined, vec![grant("stripe", "charge")]);
        assert_eq!(home.store.changes.borrow().len(), 1, "a decline saves nothing");
        assert!(home.log.0.borrow().contains(&Event::Declined { key: "stripe".into(), command: "charge".into() }));

        assert_eq!(home.setup(&Script::new(&["y"]), None).unwrap().allowed, vec![grant("stripe", "charge")]);
        assert!(home.setup(&Script::new(&[]), None).unwrap().is_empty(), "nothing waits, nothing is asked");
    }

    #[test]
    fn pattern_keys_are_offered_one_by_one_only_when_new_or_asked_for() {
        let home = Home::new(&[("stars", &["api.github.com"], &["github/*"])]);
        home.request("github/work", &["api.github.com"], &[]);
        home.request("github/home", &["api.github.com"], &[]);
        let term = Script::new(&["", VALUE, "", VALUE, "y", "n"]);
        let report = home.setup(&term, None).unwrap();
        assert!(term.saw("stars wants to use your keys github/home, github/work"));
        assert!(term.saw("Allow stars to use github/work too?"));
        assert_eq!(report.allowed, vec![grant("github/home", "stars")]);
        assert_eq!(report.declined, vec![grant("github/work", "stars")]);

        assert!(home.setup(&Script::new(&[]), None).unwrap().is_empty(), "a sweep leaves declined accounts alone");
        let report = home.setup(&Script::new(&["y"]), Some("stars")).unwrap();
        assert_eq!(report.allowed, vec![grant("github/work", "stars")]);
    }

    #[test]
    fn a_named_command_asks_for_keys_nobody_requested() {
        let home = Home::new(&[
            ("one", &["api.stripe.com", "*"], &["stripe"]),
            ("two", &["api.stripe.com", "hooks.slack.com"], &["stripe", "slack"]),
        ]);
        let term = Script::new(&["", VALUE, "y"]);
        assert_eq!(home.setup(&term, Some("one")).unwrap().added, vec!["stripe"]);
        assert!(term.saw("Key stripe is missing\n  used by one, two"));
        assert!(term.saw("Hosts it may go to (Enter keeps api.stripe.com, - skips this key): "));

        let term = Script::new(&["", "y"]);
        let report = home.setup(&term, Some("two")).unwrap();
        assert!(term.saw("the command calls api.stripe.com, hooks.slack.com"));
        assert!(term.saw("Hosts it may go to (empty skips this key): "), "two hosts: no default");
        assert_eq!(report.skipped, vec!["slack"]);
        assert_eq!(report.allowed, vec![grant("stripe", "two")]);

        assert!(home.setup(&Script::new(&[]), Some("nope")).unwrap_err().to_string().contains("no command named"));
    }

    #[test]
    fn a_named_command_leaves_other_requests_waiting() {
        let home = Home::new(&[("charge", &["api.stripe.com"], &["stripe"])]);
        home.request("stripe", &["api.stripe.com"], &[]);
        home.request("maps", &["maps.googleapis.com"], &[]);
        home.setup(&Script::new(&["", VALUE, "y"]), Some("charge")).unwrap();
        let left: Vec<String> = requests::load(&home.requests()).unwrap().requests.into_iter().map(|r| r.name).collect();
        assert_eq!(left, vec!["maps"]);
    }

    #[test]
    fn requests_for_keys_added_another_way_are_dropped() {
        let home = Home::new(&[]);
        home.request("maps", &["maps.googleapis.com"], &[]);
        let entry = SecretEntry {
            value: SecretValue::new(VALUE.into()).unwrap(),
            hosts: vec!["maps.googleapis.com".into()],
            query_params: vec![],
            commands: BTreeMap::new(),
        };
        home.store.save(&VaultData::default().with_secret("maps", entry), "test").unwrap();
        assert!(home.setup(&Script::new(&[]), None).unwrap().is_empty());
        assert!(requests::load(&home.requests()).unwrap().requests.is_empty());
    }

    #[test]
    fn a_key_you_already_had_is_named_first_at_touch_id() {
        let home = Home::new(&[("evil", &["api.github.com"], &["github", "k0", "k1"])]);
        let entry = SecretEntry {
            value: SecretValue::new(VALUE.into()).unwrap(),
            hosts: vec!["api.github.com".into()],
            query_params: vec![],
            commands: BTreeMap::new(),
        };
        home.store.save(&VaultData::default().with_secret("github", entry), "test").unwrap();
        home.request("k0", &["a.example"], &[]);
        home.request("k1", &["b.example"], &[]);
        let term = Script::new(&["", VALUE, "", VALUE, "y", "y", "y"]);
        home.setup(&term, None).unwrap();
        let changes = home.store.changes.borrow();
        assert_eq!(
            changes[1],
            "let the command evil use the API key github; add the API key k0 for a.example; \
             add the API key k1 for b.example; let the command evil use the API keys k0, k1"
        );
    }

    #[test]
    fn broken_request_entries_are_skipped_and_cleaned_up() {
        let home = Home::new(&[]);
        let file = r#"{"requests":[{"name":"bad","hosts":["localhost"]},{"name":"maps","hosts":["maps.googleapis.com"],"why":"Maps"}]}"#;
        fs::write(home.requests(), file).unwrap();
        let report = home.setup(&Script::new(&["", VALUE]), None).unwrap();
        assert_eq!((report.added, report.ignored_requests), (vec!["maps".to_string()], 1));
        let left = requests::load(&home.requests()).unwrap();
        assert_eq!((left.requests.len(), left.ignored), (0, 0));
    }

    #[test]
    fn an_unreadable_command_is_skipped_in_a_sweep() {
        let home = Home::new(&[("broken", &["api.stripe.com"], &["stripe"]), ("charge", &["api.stripe.com"], &["stripe"])]);
        home.request("stripe", &["api.stripe.com"], &[]);
        fs::remove_file(home.dir.path().join("broken/run.lua")).unwrap();
        let report = home.setup(&Script::new(&["", VALUE, "y"]), None).unwrap();
        assert_eq!(report.allowed, vec![grant("stripe", "charge")]);
        assert!(home.setup(&Script::new(&["y"]), Some("broken")).is_err(), "a named command still fails loudly");
    }
}
