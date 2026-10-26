use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use url::Url;

use super::token::{self, Tokens};
use super::{
    Cached, OAuth, TokenCache, expires_at, new_cache_key, normalize_client_id, normalize_endpoint, normalize_scope,
    random_text,
};
use crate::cli::screen::printable;
use crate::command::registry::Registry;
use crate::vault::commands::{CheckedRules, Rules, Terminal, destination};
use crate::vault::log::{AuditLog, Event};
use crate::vault::names::{NAME_RULES, is_secret_name};
use crate::vault::{SecretEntry, SecretSummary, SecretValue, VaultStore};

const CALLBACK_PATH: &str = "/callback";
const WAIT: Duration = Duration::from_mins(5);
const POLL: Duration = Duration::from_millis(50);
const MAX_VISITS: usize = 20;
const VISIT_WAIT: Duration = Duration::from_secs(5);
const MAX_HEAD_BYTES: usize = 16 * 1024;
const MAX_PARAM_LEN: usize = 256;
const RESERVED_PARAMS: [&str; 7] =
    ["client_id", "code_challenge", "code_challenge_method", "redirect_uri", "response_type", "scope", "state"];

pub trait Browser {
    fn open(&self, url: &str) -> Result<()>;
}

pub struct SystemBrowser;

impl Browser for SystemBrowser {
    fn open(&self, url: &str) -> Result<()> {
        let status = Command::new("/usr/bin/open")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("could not start /usr/bin/open")?;
        ensure!(status.success(), "/usr/bin/open failed");
        Ok(())
    }
}

pub struct SignIn<'a> {
    pub name: &'a str,
    pub rules: Rules<'a>,
    pub auth_url: Option<&'a str>,
    pub token_url: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub scopes: &'a [String],
    pub auth_params: &'a [String],
    pub port: Option<u16>,
}

pub struct Tools<'a> {
    pub store: &'a dyn VaultStore,
    pub log: &'a dyn AuditLog,
    pub term: &'a dyn Terminal,
    pub browser: &'a dyn Browser,
    pub cache: &'a TokenCache,
    pub registry: &'a Registry,
}

struct Settings {
    auth_url: String,
    token_url: String,
    client_id: String,
    scopes: Vec<String>,
    auth_params: BTreeMap<String, String>,
    port: Option<u16>,
}

pub fn sign_in(tools: &Tools, request: &SignIn) -> Result<SecretSummary> {
    let name = request.name;
    ensure!(is_secret_name(name), "{name:?} is not a valid secret name ({NAME_RULES})");
    let vault = tools.store.load()?;
    let existing = vault.get(name);
    let rules = rules_for(request, existing)?;
    let kept = existing.and_then(|entry| entry.oauth.as_ref());
    let settings = settings(request, kept)?;
    let keepable = kept.filter(|old| old.token_url == settings.token_url).and_then(|old| old.client_secret.as_ref());
    let moved = kept.is_some_and(|old| old.token_url != settings.token_url);
    let client_secret = ask_client_secret(tools.term, name, keepable, moved)?;
    let oauth = OAuth {
        auth_url: settings.auth_url,
        token_url: settings.token_url,
        client_id: settings.client_id,
        client_secret,
        scopes: settings.scopes,
        auth_params: settings.auth_params,
        port: settings.port,
        cache_key: new_cache_key()?,
    };
    let tokens = authorize(tools, &oauth)?;
    let provider = oauth.auth_host();
    let sentence = change(name, existing, &oauth, &rules);
    let commands = existing.map(|entry| entry.commands.clone()).unwrap_or_default();
    let (entry, cached) = signed_in(rules, oauth, tokens, commands)?;
    tools.store.save(&vault.with_secret(name, entry.clone()), &sentence)?;
    if let (Some(oauth), Some(cached)) = (&entry.oauth, cached)
        && let Err(err) = tools.cache.write(name, &oauth.cache_key, &cached)
    {
        eprintln!("toolbox: signed in, but could not keep the first token, so the first run asks the server: {err:#}");
    }
    tools.log.record(Event::SignedIn { key: name.to_string(), hosts: entry.hosts.clone(), provider });
    Ok(entry.summary(name, tools.registry))
}

fn rules_for(request: &SignIn, existing: Option<&SecretEntry>) -> Result<CheckedRules> {
    let rules = &request.rules;
    if !rules.hosts.is_empty() {
        return rules.check();
    }
    let partial = [rules.query_params, rules.methods, rules.paths, rules.confirm].iter().any(|given| !given.is_empty());
    ensure!(!partial, "give --host too: --query-param, --method, --path and --confirm are set together with the hosts");
    let entry = existing.ok_or_else(|| anyhow!("give at least one --host the key may be sent to"))?;
    Ok(CheckedRules {
        hosts: entry.hosts.clone(),
        query_params: entry.query_params.clone(),
        methods: entry.methods.clone(),
        paths: entry.paths.clone(),
        confirm: entry.confirm.clone(),
    })
}

fn settings(request: &SignIn, kept: Option<&OAuth>) -> Result<Settings> {
    let pick = |given: Option<&str>, old: Option<&String>, flag: &str| {
        given
            .map(str::to_string)
            .or_else(|| old.cloned())
            .ok_or_else(|| anyhow!("give {flag}: the provider's developer docs list it"))
    };
    let auth_url = pick(request.auth_url, kept.map(|o| &o.auth_url), "--auth-url")?;
    let token_url = pick(request.token_url, kept.map(|o| &o.token_url), "--token-url")?;
    let client_id = pick(request.client_id, kept.map(|o| &o.client_id), "--client-id")?;
    let scopes = match (request.scopes, kept) {
        ([], Some(old)) => old.scopes.clone(),
        (given, _) => given.iter().map(|s| normalize_scope(s)).collect::<Result<_>>()?,
    };
    let auth_params = match (request.auth_params, kept) {
        ([], Some(old)) => old.auth_params.clone(),
        (given, _) => given.iter().map(|p| auth_param(p)).collect::<Result<_>>()?,
    };
    Ok(Settings {
        auth_url: normalize_endpoint("--auth-url", &auth_url)?,
        token_url: normalize_endpoint("--token-url", &token_url)?,
        client_id: normalize_client_id(&client_id)?,
        scopes,
        auth_params,
        port: request.port.or_else(|| kept.and_then(|old| old.port)),
    })
}

fn auth_param(raw: &str) -> Result<(String, String)> {
    let invalid = || anyhow!("{raw:?} is not an --auth-param: use name=value, like access_type=offline");
    let (name, value) = raw.split_once('=').ok_or_else(invalid)?;
    let (name, value) = (name.trim(), value.trim());
    let name_ok = !name.is_empty()
        && name.len() <= MAX_PARAM_LEN
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    let value_ok = value.len() <= MAX_PARAM_LEN && value.chars().all(|c| c.is_ascii_graphic());
    ensure!(name_ok && value_ok, invalid());
    ensure!(!RESERVED_PARAMS.contains(&name), "--auth-param can't set {name}: toolbox sets it");
    Ok((name.to_string(), value.to_string()))
}

fn ask_client_secret(
    term: &dyn Terminal,
    name: &str,
    kept: Option<&SecretValue>,
    moved: bool,
) -> Result<Option<SecretValue>> {
    if moved {
        term.show("The token URL changed, so the client secret isn't reused: type it again.")?;
    }
    let prompt = match kept {
        Some(_) => format!("Client secret for {name} (input is hidden, Enter keeps the current one, - for none): "),
        None => format!("Client secret for {name} (input is hidden, Enter if the provider gave you none): "),
    };
    match term.read_secret(&prompt)?.trim() {
        "" => Ok(kept.cloned()),
        "-" => Ok(None),
        typed => Ok(Some(SecretValue::new(typed.to_string()).context("that client secret can't be used")?)),
    }
}

fn authorize(tools: &Tools, oauth: &OAuth) -> Result<Tokens> {
    let port = oauth.port.unwrap_or(0);
    let listener = TcpListener::bind(("127.0.0.1", port))
        .with_context(|| format!("could not listen on 127.0.0.1:{port} for the sign-in to come back"))?;
    let redirect_uri = format!("http://127.0.0.1:{}{CALLBACK_PATH}", listener.local_addr()?.port());
    let (state, verifier) = (random_text()?, random_text()?);
    let link = authorization_link(oauth, &redirect_uri, &state, &verifier)?;
    tools.term.show(&printable(&format!(
        "Sign in at {} in your browser. If it doesn't open, go to:\n{link}",
        oauth.auth_host()
    )))?;
    if let Err(err) = tools.browser.open(link.as_str()) {
        tools.term.show(&format!("Could not open the browser ({err:#}). Open the link above yourself."))?;
    }
    let code = wait_for_code(&listener, &state, WAIT)?;
    token::exchange(oauth, &code, &redirect_uri, &verifier)
}

fn authorization_link(oauth: &OAuth, redirect_uri: &str, state: &str, verifier: &str) -> Result<Url> {
    let mut link = Url::parse(&oauth.auth_url).context("the --auth-url is not a URL")?;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    {
        let mut query = link.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &oauth.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        if !oauth.scopes.is_empty() {
            query.append_pair("scope", &oauth.scopes.join(" "));
        }
        for (name, value) in &oauth.auth_params {
            query.append_pair(name, value);
        }
    }
    Ok(link)
}

enum Visit {
    Code(String),
    Refused(String),
    Other,
}

fn wait_for_code(listener: &TcpListener, state: &str, wait: Duration) -> Result<String> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + wait;
    let mut visits = 0;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => {
                visits += 1;
                ensure!(visits <= MAX_VISITS, "stopped after {MAX_VISITS} visits to the sign-in page without a sign-in. Nothing changed");
                match visit(stream, state, deadline) {
                    Visit::Code(code) => return Ok(code),
                    Visit::Refused(why) => bail!("{why}. Nothing changed"),
                    Visit::Other => {}
                }
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(err) => return Err(err).context("stopped listening for the sign-in"),
        }
    }
    bail!("no sign-in came back within {} minutes. Nothing changed", wait.as_secs() / 60)
}

fn visit(mut stream: TcpStream, state: &str, deadline: Instant) -> Visit {
    let Some(target) = request_target(&stream, deadline) else {
        return Visit::Other;
    };
    let Ok(url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
        let _ = answer(&mut stream, 400, "That is not a sign-in.");
        return Visit::Other;
    };
    let pairs: BTreeMap<String, String> = url.query_pairs().into_owned().collect();
    if url.path() != CALLBACK_PATH {
        let _ = answer(&mut stream, 404, "Nothing here.");
        return Visit::Other;
    }
    if pairs.get("state").map(String::as_str) != Some(state) {
        let _ = answer(&mut stream, 400, "This sign-in did not start in your terminal, so toolbox ignored it.");
        return Visit::Other;
    }
    if let Some(error) = pairs.get("error") {
        let _ = answer(&mut stream, 200, "The sign-in did not work. Go back to your terminal.");
        let shown: String = printable(error).chars().take(MAX_PARAM_LEN).collect();
        return Visit::Refused(format!("the provider did not sign you in ({shown})"));
    }
    match pairs.get("code") {
        Some(code) if !code.is_empty() => {
            let _ = answer(&mut stream, 200, "Signed in. You can close this tab and go back to your terminal.");
            Visit::Code(code.clone())
        }
        _ => {
            let _ = answer(&mut stream, 400, "The sign-in came back without a code.");
            Visit::Other
        }
    }
}

fn request_target(stream: &TcpStream, deadline: Instant) -> Option<String> {
    stream.set_nonblocking(false).ok()?;
    let until = (Instant::now() + VISIT_WAIT).min(deadline);
    let (mut head, mut chunk) = (Vec::new(), [0u8; 1024]);
    while Instant::now() < until && head.len() < MAX_HEAD_BYTES && !head.windows(4).any(|end| end == b"\r\n\r\n") {
        let left = until.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        stream.set_read_timeout(Some(left)).ok()?;
        let read = (&*stream).read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(chunk.get(..read)?);
    }
    let text = String::from_utf8_lossy(&head);
    let mut parts = text.lines().next()?.split(' ');
    (parts.next() == Some("GET")).then_some(())?;
    parts.next().filter(|target| target.starts_with('/')).map(str::to_string)
}

fn answer(stream: &mut TcpStream, status: u16, message: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Bad Request",
    };
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>toolbox</title><p style=\"font:16px system-ui;margin:3em\">{message}</p>"
    );
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn signed_in(
    rules: CheckedRules,
    oauth: OAuth,
    tokens: Tokens,
    commands: BTreeMap<String, String>,
) -> Result<(SecretEntry, Option<Cached>)> {
    match (tokens.refresh, tokens.expires_in) {
        (Some(refresh), lifetime) => {
            let cached = Cached { access: tokens.access, refresh: refresh.clone(), expires_at: expires_at(lifetime) };
            let entry = SecretEntry { oauth: Some(oauth), ..rules.entry(refresh, commands) };
            Ok((entry, Some(cached)))
        }
        (None, None) => Ok((rules.entry(tokens.access, commands), None)),
        (None, Some(lifetime)) => bail!(
            "the provider signed you in but gave no refresh token, so the key would stop working in {} minutes. Nothing changed. Ask for offline access: for Google add --auth-param access_type=offline --auth-param prompt=consent, for Microsoft add --scope offline_access",
            lifetime / 60
        ),
    }
}

fn change(name: &str, existing: Option<&SecretEntry>, oauth: &OAuth, rules: &CheckedRules) -> String {
    let shape = SecretEntry {
        query_params: rules.query_params.clone(),
        methods: rules.methods.clone(),
        paths: rules.paths.clone(),
        confirm: rules.confirm.clone(),
        ..SecretEntry::new(oauth.cache_key.clone(), rules.hosts.clone())
    };
    let now = destination(&shape);
    let at = format!("a sign-in at {} with tokens from {}", oauth.auth_host(), oauth.token_host());
    match existing {
        None => format!("add the API key {name} from {at}, for {now}"),
        Some(old) if destination(old) == now => format!("replace the API key {name} with {at}: still {now}"),
        Some(old) => format!("replace the API key {name} with {at}: now {now}, was {}", destination(old)),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::vault::VaultData;
    use crate::vault::log::MemoryLog;
    use crate::vault::oauth::fake::{self, TokenServer, token_server};
    use crate::vault::store::MemoryStore;

    struct Person {
        client_secret: &'static str,
        seen: RefCell<Vec<String>>,
    }

    impl Terminal for Person {
        fn read_secret(&self, prompt: &str) -> Result<String> {
            self.seen.borrow_mut().push(prompt.to_string());
            Ok(self.client_secret.to_string())
        }
        fn ask(&self, _prompt: &str) -> Result<String> {
            Ok(String::new())
        }
        fn show(&self, text: &str) -> Result<()> {
            self.seen.borrow_mut().push(text.to_string());
            Ok(())
        }
        fn confirm(&self, _prompt: &str) -> Result<bool> {
            Ok(true)
        }
        fn review(&self, _summary: &str, _full: &str, _question: &str) -> Result<bool> {
            Ok(true)
        }
    }

    type Answer = fn(&str, &str) -> Vec<String>;

    struct Provider {
        answer: Answer,
        links: RefCell<Vec<Url>>,
    }

    impl Browser for Provider {
        fn open(&self, link: &str) -> Result<()> {
            let link = Url::parse(link)?;
            let pairs: BTreeMap<String, String> = link.query_pairs().into_owned().collect();
            let visits = (self.answer)(&pairs["redirect_uri"], &pairs["state"]);
            thread::spawn(move || visits.iter().for_each(|url| fake::visit(url)));
            self.links.borrow_mut().push(link);
            Ok(())
        }
    }

    fn signs_in(back: &str, state: &str) -> Vec<String> {
        vec![format!("{back}?code=fake_code_123&state={state}")]
    }

    struct Setup {
        store: MemoryStore,
        log: std::rc::Rc<MemoryLog>,
        person: Person,
        provider: Provider,
        cache: TokenCache,
        _dir: tempfile::TempDir,
    }

    impl Setup {
        fn new(answer: Answer) -> Self {
            let dir = tempfile::tempdir().unwrap();
            Self {
                store: MemoryStore::new(VaultData::default()),
                log: MemoryLog::new(),
                person: Person { client_secret: "fake_client_secret_1", seen: RefCell::new(Vec::new()) },
                provider: Provider { answer, links: RefCell::new(Vec::new()) },
                cache: TokenCache { dir: dir.path().join("oauth") },
                _dir: dir,
            }
        }

        fn sign_in(&self, request: &SignIn) -> Result<SecretSummary> {
            let registry = Registry::default();
            let tools = Tools {
                store: &self.store,
                log: &*self.log,
                term: &self.person,
                browser: &self.provider,
                cache: &self.cache,
                registry: &registry,
            };
            sign_in(&tools, request)
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(std::string::ToString::to_string).collect()
    }

    fn request<'a>(server: &'a TokenServer, hosts: &'a [String], scopes: &'a [String], params: &'a [String]) -> SignIn<'a> {
        SignIn {
            name: "google",
            rules: Rules { hosts, query_params: &[], methods: &[], paths: &[], confirm: &[] },
            auth_url: Some("http://127.0.0.1:9/auth"),
            token_url: Some(&server.url),
            client_id: Some("fake-client.apps.example.com"),
            scopes,
            auth_params: params,
            port: None,
        }
    }

    #[test]
    fn a_sign_in_stores_the_refresh_token_and_keeps_the_access_token_aside() {
        let setup = Setup::new(signs_in);
        let server = token_server(vec![(200, fake::tokens("fake_access_123", Some("fake_refresh_123"), Some(3600)))]);
        let (hosts, scopes) = (strings(&["gmail.googleapis.com"]), strings(&["https://mail.example/send"]));
        let params = strings(&["access_type=offline"]);
        let summary = setup.sign_in(&request(&server, &hosts, &scopes, &params)).unwrap();
        assert_eq!(summary.oauth.unwrap().client_id, "fake-client.apps.example.com");

        let link = setup.provider.links.borrow()[0].clone();
        let sent: BTreeMap<String, String> = link.query_pairs().into_owned().collect();
        assert_eq!((sent["response_type"].as_str(), sent["scope"].as_str()), ("code", "https://mail.example/send"));
        assert_eq!((sent["access_type"].as_str(), sent["code_challenge_method"].as_str()), ("offline", "S256"));
        let body: BTreeMap<String, String> = url::form_urlencoded::parse(server.bodies.recv().unwrap().as_bytes()).into_owned().collect();
        assert_eq!((body["grant_type"].as_str(), body["code"].as_str()), ("authorization_code", "fake_code_123"));
        assert_eq!(body["client_secret"], "fake_client_secret_1");
        assert_eq!(body["redirect_uri"], sent["redirect_uri"]);
        assert_eq!(URL_SAFE_NO_PAD.encode(Sha256::digest(body["code_verifier"].as_bytes())), sent["code_challenge"]);

        let saved = setup.store.load().unwrap();
        let google = saved.get("google").unwrap();
        assert_eq!(google.value.expose(), "fake_refresh_123");
        let oauth = google.oauth.as_ref().unwrap();
        assert_eq!(oauth.client_secret.as_ref().map(SecretValue::expose), Some("fake_client_secret_1"));
        let cached = setup.cache.read("google", &oauth.cache_key).unwrap();
        assert_eq!(cached.access.expose(), "fake_access_123");
        assert_eq!(
            *setup.store.changes.borrow(),
            ["add the API key google from a sign-in at 127.0.0.1 with tokens from 127.0.0.1, for gmail.googleapis.com"]
        );
        assert!(matches!(&setup.log.0.borrow()[0], Event::SignedIn { key, provider, .. } if key == "google" && provider == "127.0.0.1"));
        assert!(!format!("{:?}", setup.log.0.borrow()).contains("fake_"));
    }

    #[test]
    fn visits_that_did_not_start_here_are_ignored() {
        fn stranger_first(back: &str, state: &str) -> Vec<String> {
            vec![
                format!("{back}?code=evil_code&state=guessed"),
                format!("{back}?error=access_denied&state=guessed"),
                format!("http://127.0.0.1:{}/favicon.ico", Url::parse(back).unwrap().port().unwrap()),
                format!("{back}?code=fake_code_123&state={state}"),
            ]
        }
        let setup = Setup::new(stranger_first);
        let server = token_server(vec![(200, fake::tokens("fake_access_123", Some("fake_refresh_123"), None))]);
        let hosts = strings(&["api.example.com"]);
        setup.sign_in(&request(&server, &hosts, &[], &[])).unwrap();
        assert!(server.bodies.recv().unwrap().contains("code=fake_code_123"));
    }

    #[test]
    fn a_refused_sign_in_changes_nothing() {
        fn refuses(back: &str, state: &str) -> Vec<String> {
            vec![format!("{back}?error=access_denied&state={state}")]
        }
        let setup = Setup::new(refuses);
        let server = token_server(vec![]);
        let hosts = strings(&["api.example.com"]);
        let err = setup.sign_in(&request(&server, &hosts, &[], &[])).unwrap_err().to_string();
        assert_eq!(err, "the provider did not sign you in (access_denied). Nothing changed");
        assert!(setup.store.changes.borrow().is_empty());
    }

    #[test]
    fn short_lived_tokens_without_a_refresh_token_are_refused() {
        let setup = Setup::new(signs_in);
        let server = token_server(vec![(200, fake::tokens("fake_access_123", None, Some(3600)))]);
        let hosts = strings(&["api.example.com"]);
        let err = setup.sign_in(&request(&server, &hosts, &[], &[])).unwrap_err().to_string();
        assert!(err.contains("no refresh token") && err.contains("access_type=offline"), "{err}");
        assert!(setup.store.changes.borrow().is_empty());

        let lasting = token_server(vec![(200, fake::tokens("fake_lasting_123", None, None))]);
        setup.sign_in(&request(&lasting, &hosts, &[], &[])).unwrap();
        let saved = setup.store.load().unwrap();
        let google = saved.get("google").unwrap();
        assert_eq!((google.value.expose(), google.oauth.is_none()), ("fake_lasting_123", true));
    }

    #[test]
    fn signing_in_again_reuses_what_was_given_before() {
        let setup = Setup::new(signs_in);
        let first = token_server(vec![(200, fake::tokens("fake_access_123", Some("fake_refresh_123"), None))]);
        let (hosts, scopes) = (strings(&["api.example.com"]), strings(&["read"]));
        setup.sign_in(&request(&first, &hosts, &scopes, &[])).unwrap();
        let old = setup.store.load().unwrap().get("google").unwrap().with_command("mail", "fp".into());
        setup.store.save(&setup.store.load().unwrap().with_secret("google", old.clone()), "test").unwrap();

        let second = token_server(vec![(200, fake::tokens("fake_access_456", Some("fake_refresh_456"), None))]);
        let again = SignIn {
            rules: Rules { hosts: &[], query_params: &[], methods: &[], paths: &[], confirm: &[] },
            auth_url: None,
            token_url: None,
            client_id: None,
            ..request(&first, &[], &[], &[])
        };
        let moved = OAuth { token_url: second.url.clone(), ..old.oauth.clone().unwrap() };
        setup.store.save(&setup.store.load().unwrap().with_secret("google", SecretEntry { oauth: Some(moved), ..old }), "test").unwrap();
        setup.sign_in(&again).unwrap();

        let saved = setup.store.load().unwrap();
        let google = saved.get("google").unwrap();
        assert_eq!((google.value.expose(), google.hosts.as_slice()), ("fake_refresh_456", &hosts[..]));
        assert_eq!(google.commands.get("mail").map(String::as_str), Some("fp"));
        assert_eq!(google.oauth.as_ref().unwrap().scopes, scopes);
        assert!(setup.person.seen.borrow().iter().any(|seen| seen.contains("Enter keeps the current one")));
        assert_eq!(
            setup.store.changes.borrow().last().unwrap(),
            "replace the API key google with a sign-in at 127.0.0.1 with tokens from 127.0.0.1: still api.example.com"
        );
    }

    #[test]
    fn a_new_token_url_never_gets_the_kept_client_secret() {
        let setup = Setup::new(signs_in);
        let first = token_server(vec![(200, fake::tokens("fake_access_123", Some("fake_refresh_123"), None))]);
        let hosts = strings(&["api.example.com"]);
        setup.sign_in(&request(&first, &hosts, &[], &[])).unwrap();

        let elsewhere = token_server(vec![(200, fake::tokens("fake_access_456", Some("fake_refresh_456"), None))]);
        let mut quiet = Setup::new(signs_in);
        quiet.store = MemoryStore::new(setup.store.load().unwrap());
        quiet.person.client_secret = "";
        let moved = SignIn { token_url: Some(&elsewhere.url), ..request(&first, &hosts, &[], &[]) };
        quiet.sign_in(&moved).unwrap();
        let sent: BTreeMap<String, String> =
            url::form_urlencoded::parse(elsewhere.bodies.recv().unwrap().as_bytes()).into_owned().collect();
        assert!(!sent.contains_key("client_secret"), "the kept secret went to a new token URL: {sent:?}");
        assert!(quiet.person.seen.borrow().iter().any(|seen| seen.contains("token URL changed")));
        assert!(quiet.store.changes.borrow()[0].contains("with tokens from 127.0.0.1"));
    }

    #[test]
    fn settings_are_checked_before_the_browser_opens() {
        let setup = Setup::new(signs_in);
        let server = token_server(vec![]);
        let hosts = strings(&["api.example.com"]);
        for params in [strings(&["state=x"]), strings(&["novalue"]), strings(&["a b=c"])] {
            assert!(setup.sign_in(&request(&server, &hosts, &[], &params)).is_err(), "{params:?}");
        }
        let plain = SignIn { auth_url: Some("http://example.com/auth"), ..request(&server, &hosts, &[], &[]) };
        assert!(setup.sign_in(&plain).unwrap_err().to_string().contains("--auth-url"));
        let nothing = SignIn { auth_url: None, ..request(&server, &hosts, &[], &[]) };
        assert!(setup.sign_in(&nothing).unwrap_err().to_string().contains("give --auth-url"));
        let no_hosts = request(&server, &[], &[], &[]);
        assert!(setup.sign_in(&no_hosts).unwrap_err().to_string().contains("--host"));
        let writes = strings(&["writes"]);
        let only_confirm = SignIn {
            rules: Rules { hosts: &[], query_params: &[], methods: &[], paths: &[], confirm: &writes },
            ..request(&server, &[], &[], &[])
        };
        assert!(setup.sign_in(&only_confirm).unwrap_err().to_string().contains("give --host too"));
        assert!(setup.provider.links.borrow().is_empty());
    }
}
