use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use mlua::{Lua, LuaSerdeExt, Table, Value};
use serde::{Deserialize, Serialize};
use ureq::http::{Request, Response};
use ureq::{Agent, AsSendBody, Body, Proxy};
use url::{Url, form_urlencoded};

use super::encoding::query_pairs;
use super::{seconds, ser_options};
use crate::cli::screen::{one_line, printable};
use crate::command::manifest::Permissions;
use crate::vault::approval::Caller;
use crate::vault::inject::{Injector, Redactor, Values, ensure_absent, mentions_vault, secret_names};
use crate::vault::log::{self as key_log, AuditLog, Event, Outcome};
use crate::vault::oauth::{Minter, TokenCache};
use crate::vault::{Keys, SecretValue, VaultData, VaultStore, scope};

const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BODY_BYTES: u64 = 20 * 1024 * 1024;
const MAX_REDIRECTS: u32 = 10;
const SUGAR_METHODS: &[&str] = &["get", "post", "put", "patch", "delete"];

#[derive(Debug)]
pub struct RequestSpec {
    pub method: String,
    pub url: String,
    pub options: RequestOptions,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequest {
    #[serde(default = "default_method")]
    method: String,
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    json: Option<serde_json::Value>,
    #[serde(default)]
    form: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    query: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    timeout: Option<f64>,
}

impl From<RawRequest> for RequestSpec {
    fn from(raw: RawRequest) -> Self {
        Self {
            method: raw.method,
            url: raw.url,
            options: RequestOptions {
                headers: raw.headers,
                body: raw.body,
                json: raw.json,
                form: raw.form,
                query: raw.query,
                timeout: raw.timeout,
            },
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestOptions {
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub json: Option<serde_json::Value>,
    #[serde(default)]
    pub form: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    pub query: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub timeout: Option<f64>,
}

fn default_method() -> String {
    "GET".to_string()
}

#[derive(Debug, Serialize)]
pub struct ResponseData {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<serde_json::Value>,
}

struct LazyVault {
    store: Box<dyn VaultStore>,
    loaded: RefCell<Option<Rc<VaultData>>>,
    minted: RefCell<Vec<(String, SecretValue)>>,
}

impl LazyVault {
    fn get(&self) -> Result<Rc<VaultData>> {
        if let Some(data) = self.loaded.borrow().as_ref() {
            return Ok(Rc::clone(data));
        }
        let data = Rc::new(self.store.load()?);
        *self.loaded.borrow_mut() = Some(Rc::clone(&data));
        Ok(data)
    }

    fn redactor(&self) -> Redactor {
        self.loaded
            .borrow()
            .as_ref()
            .map(|data| Redactor::new(data, &self.minted.borrow()))
            .unwrap_or_default()
    }
}

pub struct HttpClient {
    allowed_hosts: Vec<String>,
    caller: Caller,
    vault: LazyVault,
    plain: Agent,
    secret_safe: Agent,
    log: Box<dyn AuditLog>,
    tokens: TokenCache,
}

#[derive(Debug)]
struct Hop {
    method: String,
    url: Url,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

type Pairs = Vec<(String, String)>;

struct Outgoing {
    method: String,
    url: Url,
    headers: Pairs,
    query: Pairs,
    body: Vec<u8>,
    timeout: Option<Duration>,
}

impl Outgoing {
    fn new(spec: RequestSpec, url: Url) -> Result<Self> {
        ensure_absent("url", &spec.url)?;
        let query = query_pairs(&spec.options.query)?;
        let timeout = spec.options.timeout.map(seconds).transpose()?;
        let (body, content_type) = encode_body(&spec.options)?;
        ensure_absent("body", &String::from_utf8_lossy(&body))?;
        let has_type = spec.options.headers.keys().any(|k| k.eq_ignore_ascii_case("content-type"));
        let added = content_type
            .filter(|_| !has_type)
            .map(|ct| ("content-type".to_string(), ct.to_string()));
        let headers = spec.options.headers.into_iter().chain(added).collect();
        Ok(Self { method: spec.method, url, headers, query, body, timeout })
    }

    fn pairs(&self) -> impl Iterator<Item = &(String, String)> {
        self.headers.iter().chain(&self.query)
    }

    fn uses_vault(&self) -> bool {
        self.pairs().any(|(k, v)| mentions_vault(k) || mentions_vault(v))
    }

    fn keys(&self) -> Vec<String> {
        let names: BTreeSet<String> = self.pairs().flat_map(|(_, value)| secret_names(value)).collect();
        names.into_iter().collect()
    }

    fn into_hop(self, filled: Option<(Pairs, Pairs)>) -> Hop {
        let (headers, query) = filled.unwrap_or((self.headers, self.query));
        let mut url = self.url;
        append_query(&mut url, &query);
        Hop { method: self.method, url, headers, body: self.body }
    }
}

const DROPPED_ON_REDIRECT: &[&str] = &["authorization", "cookie", "content-length"];

impl HttpClient {
    pub fn new(perms: &Permissions, caller: Caller, keys: Keys) -> Self {
        Self {
            allowed_hosts: perms.http.iter().map(|h| h.to_ascii_lowercase()).collect(),
            caller,
            vault: LazyVault {
                store: keys.store,
                loaded: RefCell::new(None),
                minted: RefCell::new(Vec::new()),
            },
            plain: agent(Proxy::try_from_env()),
            secret_safe: agent(None),
            log: keys.log,
            tokens: keys.tokens,
        }
    }

    pub fn send(&self, spec: RequestSpec) -> Result<ResponseData> {
        let url = Url::parse(&spec.url).with_context(|| format!("invalid url {:?}", spec.url))?;
        self.check_host(&url)?;
        let outgoing = Outgoing::new(spec, url)?;
        if outgoing.uses_vault() {
            return self.send_with_secrets(outgoing);
        }
        let timeout = outgoing.timeout;
        let redactor = self.vault.redactor();
        let response = self
            .follow(outgoing.into_hop(None), timeout)
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        Ok(redact_response(&redactor, response))
    }

    fn send_with_secrets(&self, outgoing: Outgoing) -> Result<ResponseData> {
        let keys = outgoing.keys();
        let request = logged_request(&outgoing.method, &outgoing.url);
        let vault = self.vault.get()?;
        let injector = Injector {
            vault: &vault,
            caller: &self.caller,
            method: &outgoing.method,
            url: &outgoing.url,
        };
        let (filled, confirmed) = match self.prepare(&injector, &outgoing) {
            Ok(prepared) => prepared,
            Err(err) => {
                let reason = format!("{err:#}");
                self.log.record(Event::Refused { keys, command: self.caller.name.clone(), request, reason });
                return Err(err);
            }
        };
        let timeout = outgoing.timeout;
        let redactor = self.vault.redactor();
        let response = execute(&self.secret_safe, &outgoing.into_hop(Some(filled)), timeout)
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))));
        let outcome = match &response {
            Ok(done) => Outcome::Status(done.status),
            Err(err) => Outcome::Failed(err.to_string()),
        };
        self.log.record(Event::Used { keys, command: self.caller.name.clone(), request, outcome, confirmed });
        Ok(redact_response(&redactor, response?))
    }

    fn prepare(&self, injector: &Injector, outgoing: &Outgoing) -> Result<((Pairs, Pairs), bool)> {
        scope::normalize_method(&outgoing.method)?;
        let names = injector.authorize_all(&outgoing.headers, &outgoing.query)?;
        refuse_method_override(injector.vault, &names, outgoing)?;
        let asks = injector.needs_confirmation(&names);
        if !asks.is_empty() {
            let what = confirmation(&self.caller.name, &outgoing.method, &outgoing.url, &asks);
            self.vault.store.confirm_use(&what).map_err(|why| {
                anyhow!(
                    "the user did not confirm this request ({why:#}), so nothing was sent. The key is set to ask for Touch ID before each {} request: don't retry unless the user asks you to",
                    outgoing.method.to_ascii_uppercase()
                )
            })?;
        }
        let values = names
            .iter()
            .map(|name| Ok((name.clone(), self.value_for(name, injector.vault)?)))
            .collect::<Result<Values>>()?;
        let headers = injector.headers(&outgoing.headers, &values)?;
        let query = injector.query(&outgoing.query, &values)?;
        Ok(((headers, query), !asks.is_empty()))
    }

    fn value_for(&self, name: &str, vault: &VaultData) -> Result<SecretValue> {
        let entry = vault.get(name).ok_or_else(|| anyhow!("no secret named {name:?} in the vault"))?;
        let Some(oauth) = &entry.oauth else {
            return Ok(entry.value.clone());
        };
        let tokens = Minter { cache: &self.tokens, log: &*self.log, command: &self.caller.name }
            .access_token(name, entry, oauth)?;
        let mut minted = self.vault.minted.borrow_mut();
        for token in [&tokens.access, &tokens.refresh] {
            if !minted.iter().any(|(_, known)| known == token) {
                minted.push((name.to_string(), token.clone()));
            }
        }
        Ok(tokens.access)
    }

    fn follow(&self, mut hop: Hop, timeout: Option<Duration>) -> Result<ResponseData> {
        let deadline = Instant::now() + timeout.unwrap_or(TIMEOUT);
        for _ in 0..=MAX_REDIRECTS {
            let left = deadline.saturating_duration_since(Instant::now());
            let response = execute(&self.plain, &hop, Some(left))?;
            let Some(next) = redirect(&hop, &response)? else {
                return Ok(response);
            };
            self.check_host(&next.url).with_context(|| {
                format!("{} redirected to another host", hop.url.host_str().unwrap_or("?"))
            })?;
            hop = next;
        }
        bail!("stopped after {MAX_REDIRECTS} redirects")
    }

    fn check_host(&self, url: &Url) -> Result<()> {
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let allowed = self.allowed_hosts.iter().any(|h| h == "*" || *h == host);
        anyhow::ensure!(
            allowed,
            "host {host:?} is not listed in this command's permissions.http"
        );
        Ok(())
    }
}

const MAX_SHOWN_PATH: usize = 120;

fn refuse_method_override(vault: &VaultData, names: &BTreeSet<String>, outgoing: &Outgoing) -> Result<()> {
    let guarded: Vec<&str> = names
        .iter()
        .filter(|name| vault.get(name).is_some_and(|entry| !entry.methods.is_empty() || !entry.confirm.is_empty()))
        .map(String::as_str)
        .collect();
    if guarded.is_empty() {
        return Ok(());
    }
    let sent = scope::Sent { headers: &outgoing.headers, query: &outgoing.query, url: &outgoing.url, body: &outgoing.body };
    match scope::method_override(&sent) {
        Some(found) => bail!(
            "the key {} has method or confirm rules, so it can't be sent with {found}: some servers use it to change the method",
            guarded.join(", ")
        ),
        None => Ok(()),
    }
}

fn confirmation(command: &str, method: &str, url: &Url, keys: &[String]) -> String {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    let path: String = printable(url.path()).chars().take(MAX_SHOWN_PATH).collect();
    let method = printable(&one_line(&method.to_ascii_uppercase()));
    let cut = if url.path().chars().count() > MAX_SHOWN_PATH { "..." } else { "" };
    let plural = if keys.len() > 1 { "s" } else { "" };
    format!("let the command {command} send {method} {host}{path}{cut} with your API key{plural} {}", keys.join(", "))
}

fn logged_request(method: &str, url: &Url) -> key_log::Request {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    key_log::Request {
        method: method.to_ascii_uppercase(),
        host: match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        },
        path: url.path().to_string(),
    }
}

fn agent(proxy: Option<Proxy>) -> Agent {
    Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .proxy(proxy)
        .timeout_global(Some(TIMEOUT))
        .build()
        .into()
}

fn encode_body(options: &RequestOptions) -> Result<(Vec<u8>, Option<&'static str>)> {
    match (&options.body, &options.json, &options.form) {
        (Some(body), None, None) => Ok((body.clone().into_bytes(), None)),
        (None, Some(json), None) => Ok((serde_json::to_vec(json)?, Some("application/json"))),
        (None, None, Some(form)) => {
            let encoded = encode_pairs("body", form)?;
            Ok((encoded.into_bytes(), Some("application/x-www-form-urlencoded")))
        }
        (None, None, None) => Ok((Vec::new(), None)),
        _ => Err(anyhow!("use only one of body, json or form")),
    }
}

fn append_query(url: &mut Url, pairs: &[(String, String)]) {
    if !pairs.is_empty() {
        let encoded = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let query = match url.query() {
            Some(existing) if !existing.is_empty() => format!("{existing}&{encoded}"),
            _ => encoded,
        };
        url.set_query(Some(&query));
    }
}

fn encode_pairs(location: &str, params: &BTreeMap<String, serde_json::Value>) -> Result<String> {
    let pairs = query_pairs(params)?;
    for (key, value) in &pairs {
        ensure_absent(location, key)?;
        ensure_absent(location, value)?;
    }
    Ok(form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish())
}

fn redirect(hop: &Hop, response: &ResponseData) -> Result<Option<Hop>> {
    let Some(location) = response.headers.get("location") else {
        return Ok(None);
    };
    if !(300..400).contains(&response.status) || response.status == 304 {
        return Ok(None);
    }
    let method = hop.method.to_ascii_uppercase();
    let method = match (response.status, method.as_str()) {
        (307 | 308, "POST" | "PUT" | "PATCH" | "DELETE") => return Ok(None),
        (307 | 308, _) | (_, "GET" | "HEAD") => method,
        _ => "GET".to_string(),
    };
    let url = hop
        .url
        .join(location)
        .with_context(|| format!("invalid redirect to {location:?}"))?;
    let headers = hop
        .headers
        .iter()
        .filter(|(name, _)| !DROPPED_ON_REDIRECT.iter().any(|d| name.eq_ignore_ascii_case(d)))
        .cloned()
        .collect();
    Ok(Some(Hop {
        method,
        url,
        headers,
        body: Vec::new(),
    }))
}

fn execute(agent: &Agent, hop: &Hop, timeout: Option<Duration>) -> Result<ResponseData> {
    let builder = hop.headers.iter().fold(
        Request::builder()
            .method(hop.method.to_ascii_uppercase().as_str())
            .uri(hop.url.as_str()),
        |builder, (name, value)| builder.header(name.as_str(), value.as_str()),
    );
    let mut response = if hop.body.is_empty() {
        run(agent, builder.body(ureq::SendBody::none()).context("invalid request")?, timeout)
    } else {
        run(agent, builder.body(hop.body.as_slice()).context("invalid request")?, timeout)
    }
    .map_err(|e| anyhow!("request to {} failed: {e}", hop.url.host_str().unwrap_or("?")))?;

    let headers = response.headers().iter().fold(
        BTreeMap::<String, String>::new(),
        |mut acc, (name, value)| {
            let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
            acc.entry(name.as_str().to_string())
                .and_modify(|existing| *existing = format!("{existing}, {value}"))
                .or_insert(value);
            acc
        },
    );
    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_BODY_BYTES)
        .read_to_vec()
        .context("could not read the response body")?;
    Ok(ResponseData {
        status: response.status().as_u16(),
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
        json: None,
    })
}

fn run<S: AsSendBody>(
    agent: &Agent,
    request: Request<S>,
    timeout: Option<Duration>,
) -> Result<Response<Body>, ureq::Error> {
    let request = match timeout {
        Some(limit) => agent.configure_request(request).timeout_global(Some(limit)).build(),
        None => request,
    };
    agent.run(request)
}

fn redact_response(redactor: &Redactor, response: ResponseData) -> ResponseData {
    let body = redactor.redact(&response.body);
    let headers = response
        .headers
        .into_iter()
        .map(|(name, value)| (name, redactor.redact(&value)))
        .collect();
    let (body, json) = match parse_json(&body) {
        Some(value) if json_has_secret(redactor, &value) => {
            let clean = redact_json(redactor, value);
            (clean.to_string(), Some(clean))
        }
        parsed => (body, parsed),
    };
    ResponseData {
        status: response.status,
        headers,
        body,
        json,
    }
}

fn json_has_secret(redactor: &Redactor, value: &serde_json::Value) -> bool {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::String(text) if redactor.finds(text) => return true,
            serde_json::Value::Array(items) => pending.extend(items),
            serde_json::Value::Object(map) => {
                if map.keys().any(|key| redactor.finds(key)) {
                    return true;
                }
                pending.extend(map.values());
            }
            _ => {}
        }
    }
    false
}

fn redact_json(redactor: &Redactor, mut root: serde_json::Value) -> serde_json::Value {
    let mut pending = vec![&mut root];
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::String(text) => *text = redactor.redact(text),
            serde_json::Value::Array(items) => pending.extend(items),
            serde_json::Value::Object(map) => {
                *map = std::mem::take(map)
                    .into_iter()
                    .map(|(key, item)| (redactor.redact(&key), item))
                    .collect();
                pending.extend(map.values_mut());
            }
            _ => {}
        }
    }
    root
}

fn parse_json(body: &str) -> Option<serde_json::Value> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        serde_json::from_str(body).ok()
    } else {
        None
    }
}

pub fn install(lua: &Lua, client: &Rc<HttpClient>) -> mlua::Result<()> {
    let http: Table = lua.create_table()?;
    let request_client = Rc::clone(client);
    http.set(
        "request",
        lua.create_function(move |lua, spec: Value| {
            let raw: RawRequest = lua.from_value(spec)?;
            send_to_lua(lua, &request_client, raw.into())
        })?,
    )?;
    for method in SUGAR_METHODS {
        let method_client = Rc::clone(client);
        let verb = method.to_ascii_uppercase();
        http.set(
            *method,
            lua.create_function(move |lua, (url, opts): (String, Option<Value>)| {
                let options: RequestOptions = match opts {
                    Some(value) => lua.from_value(value)?,
                    None => RequestOptions::default(),
                };
                let spec = RequestSpec {
                    method: verb.clone(),
                    url,
                    options,
                };
                send_to_lua(lua, &method_client, spec)
            })?,
        )?;
    }
    lua.globals().set("http", http)
}

fn send_to_lua(lua: &Lua, client: &HttpClient, spec: RequestSpec) -> mlua::Result<Value> {
    let response = client.send(spec).map_err(mlua::Error::external)?;
    lua.to_value_with(&response, ser_options())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::store::MemoryStore;
    use crate::vault::{SecretEntry, SecretValue};

    fn client(http: &[&str], vault: &[&str]) -> HttpClient {
        let perms = Permissions {
            http: http.iter().map(std::string::ToString::to_string).collect(),
            vault: vault.iter().map(std::string::ToString::to_string).collect(),
            ..Permissions::default()
        };
        let caller = Caller {
            name: "t".into(),
            declared: perms.vault.clone(),
            fingerprint: "t".into(),
        };
        let keys = Keys {
            store: Box::new(MemoryStore::new(VaultData::default())),
            log: Box::new(crate::vault::log::MemoryLog::new()),
            tokens: TokenCache { dir: std::env::temp_dir().join("toolbox-unused-token-cache") },
        };
        HttpClient::new(&perms, caller, keys)
    }

    fn spec(url: &str, options: RequestOptions) -> RequestSpec {
        RequestSpec {
            method: "GET".into(),
            url: url.into(),
            options,
        }
    }

    #[test]
    fn refuses_hosts_not_in_permissions() {
        let err = client(&["api.github.com"], &[])
            .send(spec("https://evil.example/", RequestOptions::default()))
            .unwrap_err();
        assert!(err.to_string().contains("permissions.http"));
    }

    #[test]
    fn refuses_placeholders_outside_headers() {
        let c = client(&["*"], &["github"]);
        let in_url = c.send(spec("https://x.example/?k={{vault:github}}", RequestOptions::default()));
        assert!(in_url.unwrap_err().to_string().contains("only allowed in header values"));

        let in_body = c.send(spec(
            "https://x.example/",
            RequestOptions {
                json: Some(serde_json::json!({ "token": "{{vault:github}}" })),
                ..RequestOptions::default()
            },
        ));
        assert!(in_body.unwrap_err().to_string().contains("only allowed in header values"));
    }

    #[test]
    fn refuses_more_than_one_body() {
        let options = RequestOptions {
            body: Some("x".into()),
            json: Some(serde_json::json!({})),
            ..RequestOptions::default()
        };
        assert!(encode_body(&options).is_err());
        let options = RequestOptions {
            json: Some(serde_json::json!({})),
            form: Some(BTreeMap::new()),
            ..RequestOptions::default()
        };
        assert!(encode_body(&options).unwrap_err().to_string().contains("only one of body, json or form"));
    }

    fn params(value: serde_json::Value) -> BTreeMap<String, serde_json::Value> {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn form_bodies_are_url_encoded() {
        let options = RequestOptions {
            form: Some(params(serde_json::json!({ "name": "a b", "n": 1 }))),
            ..RequestOptions::default()
        };
        let (body, content_type) = encode_body(&options).unwrap();
        assert_eq!(String::from_utf8(body).unwrap(), "n=1&name=a+b");
        assert_eq!(content_type, Some("application/x-www-form-urlencoded"));
    }

    #[test]
    fn query_is_added_to_the_url() {
        let mut url = Url::parse("https://x.example/search?lang=en").unwrap();
        let pairs = query_pairs(&params(serde_json::json!({ "q": "a&b", "page": 2 }))).unwrap();
        append_query(&mut url, &pairs);
        assert_eq!(url.as_str(), "https://x.example/search?lang=en&page=2&q=a%26b");

        let mut bare = Url::parse("https://x.example/").unwrap();
        append_query(&mut bare, &[]);
        assert_eq!(bare.as_str(), "https://x.example/");
    }

    #[test]
    fn query_placeholders_need_the_secret_and_form_ones_are_refused() {
        let c = client(&["*"], &["github"]);
        let in_query = c.send(spec(
            "https://x.example/",
            RequestOptions {
                query: params(serde_json::json!({ "key": "{{vault:github}}" })),
                ..RequestOptions::default()
            },
        ));
        let err = in_query.unwrap_err().to_string();
        assert!(err.contains("tb self vault request github --host x.example --query-param key"), "{err}");
        let in_form = c.send(spec(
            "https://x.example/",
            RequestOptions {
                form: Some(params(serde_json::json!({ "key": "{{vault:github}}" }))),
                ..RequestOptions::default()
            },
        ));
        assert!(in_form.unwrap_err().to_string().contains("found one in the body"));
    }

    #[test]
    fn missing_secret_is_reported_before_any_request() {
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".to_string(), "Bearer {{vault:github}}".to_string());
        let err = client(&["*"], &["github"])
            .send(spec("https://x.example/", RequestOptions { headers, ..RequestOptions::default() }))
            .unwrap_err();
        assert!(err.to_string().contains("tb self vault request github --host x.example --why"), "{err}");
    }

    #[test]
    fn timeout_option_limits_the_wait() {
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}/", silent.local_addr().unwrap().port());
        let started = std::time::Instant::now();
        let err = client(&["127.0.0.1"], &[])
            .send(spec(&url, RequestOptions { timeout: Some(0.3), ..RequestOptions::default() }))
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5), "{err}");
        assert!(err.to_string().contains("timeout"), "{err}");

        let huge = client(&["127.0.0.1"], &[])
            .send(spec(&url, RequestOptions { timeout: Some(1e19), ..RequestOptions::default() }))
            .unwrap_err();
        assert!(huge.to_string().contains("not a valid number of seconds"), "{huge}");
    }

    fn hop(method: &str, headers: &[(&str, &str)]) -> Hop {
        Hop {
            method: method.into(),
            url: Url::parse("https://a.example/dir/page?x=1").unwrap(),
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: b"data".to_vec(),
        }
    }

    fn response(status: u16, location: Option<&str>) -> ResponseData {
        ResponseData {
            status,
            headers: location.map(|l| ("location".to_string(), l.to_string())).into_iter().collect(),
            body: String::new(),
            json: None,
        }
    }

    #[test]
    fn redirects_follow_ureq_rules() {
        let posted = hop("POST", &[("Authorization", "a"), ("cookie", "c"), ("Accept", "x")]);
        let next = redirect(&posted, &response(302, Some("../other"))).unwrap().unwrap();
        assert_eq!(next.method, "GET");
        assert_eq!(next.url.as_str(), "https://a.example/other");
        assert_eq!(next.headers, vec![("Accept".to_string(), "x".to_string())]);
        assert!(next.body.is_empty());

        let head = redirect(&hop("head", &[]), &response(301, Some("https://b.example/"))).unwrap().unwrap();
        assert_eq!((head.method.as_str(), head.url.as_str()), ("HEAD", "https://b.example/"));
        let get = redirect(&hop("GET", &[]), &response(307, Some("/x"))).unwrap().unwrap();
        assert_eq!(get.method, "GET");

        for (method, status, location) in [
            ("POST", 307, Some("/x")),
            ("DELETE", 308, Some("/x")),
            ("GET", 304, Some("/x")),
            ("GET", 302, None),
            ("GET", 200, Some("/x")),
        ] {
            assert!(redirect(&hop(method, &[]), &response(status, location)).unwrap().is_none());
        }
    }

    #[test]
    fn redirects_to_unlisted_hosts_are_refused() {
        let redirector = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}/", redirector.local_addr().unwrap().port());
        std::thread::spawn(move || {
            use std::io::{BufRead, Write};
            let (mut stream, _) = redirector.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            let reply = "HTTP/1.1 302 Found\r\nlocation: https://evil.example/\r\ncontent-length: 0\r\n\r\n";
            stream.write_all(reply.as_bytes()).unwrap();
        });
        let err = client(&["127.0.0.1"], &[])
            .send(spec(&url, RequestOptions { timeout: Some(5.0), ..RequestOptions::default() }))
            .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            r#"127.0.0.1 redirected to another host: host "evil.example" is not listed in this command's permissions.http"#
        );
    }

    fn redactor_for(secret: &str) -> Redactor {
        let entry = SecretEntry::new(SecretValue::new(secret.into()).unwrap(), vec![]);
        Redactor::new(&VaultData::default().with_secret("k", entry), &[])
    }

    fn with_body(body: &str) -> ResponseData {
        ResponseData {
            status: 200,
            headers: BTreeMap::new(),
            body: body.into(),
            json: None,
        }
    }

    fn answer_requests(count: usize) -> (u16, std::sync::mpsc::Receiver<String>) {
        use std::io::{BufRead, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for _ in 0..count {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let (mut head, mut line) = (String::new(), String::new());
                while reader.read_line(&mut line).unwrap() > 2 {
                    head.push_str(&line);
                    line.clear();
                }
                stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").unwrap();
                tx.send(head).unwrap();
            }
        });
        (port, rx)
    }

    fn asking_client(port: u16, store: &Rc<MemoryStore>, log: &Rc<crate::vault::log::MemoryLog>) -> HttpClient {
        let asks = SecretEntry {
            confirm: vec!["writes".into()],
            commands: [("t".to_string(), "t".to_string())].into(),
            ..SecretEntry::new(SecretValue::new("fake_mail_key_123".into()).unwrap(), vec![format!("127.0.0.1:{port}")])
        };
        *store.data.borrow_mut() = VaultData::default().with_secret("mail", asks);
        let perms = Permissions { http: vec!["127.0.0.1".into()], vault: vec!["mail".into()], ..Permissions::default() };
        let caller = Caller { name: "t".into(), declared: perms.vault.clone(), fingerprint: "t".into() };
        let tokens = TokenCache { dir: std::env::temp_dir().join("toolbox-unused-token-cache") };
        HttpClient::new(&perms, caller, Keys { store: Box::new(Rc::clone(store)), log: Box::new(Rc::clone(log)), tokens })
    }

    fn with_key(method: &str, url: &str) -> RequestSpec {
        let headers = [("Authorization".to_string(), "Bearer {{vault:mail}}".to_string())].into();
        RequestSpec { method: method.into(), url: url.into(), options: RequestOptions { headers, ..RequestOptions::default() } }
    }

    #[test]
    fn keys_set_to_ask_wait_for_the_human_before_each_write() {
        let (port, received) = answer_requests(2);
        let (store, log) = (Rc::new(MemoryStore::new(VaultData::default())), crate::vault::log::MemoryLog::new());
        let client = asking_client(port, &store, &log);
        let url = format!("http://127.0.0.1:{port}/v3/mail/send");

        store.confirm.set(false);
        let err = client.send(with_key("post", &url)).unwrap_err().to_string();
        assert!(err.contains("did not confirm") && err.contains("don't retry"), "{err}");
        assert_eq!(*store.asked.borrow(), [format!("let the command t send POST 127.0.0.1:{port}/v3/mail/send with your API key mail")]);
        assert!(received.try_recv().is_err(), "nothing may be sent before the human says yes");
        assert!(matches!(&log.0.borrow()[0], Event::Refused { reason, .. } if reason.contains("did not confirm")));

        store.confirm.set(true);
        assert_eq!(client.send(with_key("POST", &url)).unwrap().status, 200);
        assert!(received.recv().unwrap().contains("Bearer fake_mail_key_123"));
        assert!(matches!(&log.0.borrow()[1], Event::Used { confirmed: true, .. }));

        assert_eq!(client.send(with_key("GET", &url)).unwrap().status, 200);
        assert_eq!(store.asked.borrow().len(), 2, "reads don't ask");
        assert!(matches!(&log.0.borrow()[2], Event::Used { confirmed: false, .. }));
    }

    #[test]
    fn guarded_keys_refuse_odd_methods_and_method_overrides() {
        let (port, received) = answer_requests(1);
        let (store, log) = (Rc::new(MemoryStore::new(VaultData::default())), crate::vault::log::MemoryLog::new());
        let client = asking_client(port, &store, &log);
        let url = format!("http://127.0.0.1:{port}/v3/mail/send");
        let err = client.send(with_key("GET\nlet the command t read", &url)).unwrap_err().to_string();
        assert!(err.contains("is not an HTTP method"), "{err}");
        let mut overridden = with_key("GET", &url);
        overridden.options.headers.insert("X-HTTP-Method-Override".into(), "DELETE".into());
        let err = client.send(overridden).unwrap_err().to_string();
        assert!(err.contains("can't be sent with the X-HTTP-Method-Override header"), "{err}");
        assert!(store.asked.borrow().is_empty() && received.try_recv().is_err());
    }

    #[test]
    fn the_question_shows_where_the_request_goes_and_escapes_it() {
        let url = Url::parse("https://api.example.com:8443/a\u{202e}b").unwrap();
        let asked = confirmation("mail", "delete", &url, &["mail".into(), "other".into()]);
        assert_eq!(asked, "let the command mail send DELETE api.example.com:8443/a%E2%80%AEb with your API keys mail, other");
        let long = Url::parse(&format!("https://x.example/{}", "a".repeat(300))).unwrap();
        let asked = confirmation("t", "POST", &long, &["k".into()]);
        assert!(asked.contains(&format!("/{}... with", "a".repeat(MAX_SHOWN_PATH - 1))), "{asked}");
    }

    #[test]
    fn keys_in_json_escapes_are_redacted_in_json_and_body() {
        let redactor = redactor_for("abcd/efgh_1234");
        let clean = redact_response(&redactor, with_body(r#"{"a":"abcd\/efgh_1234","b":"\u0061bcd/efgh_1234","n":1}"#));
        let expected = serde_json::json!({ "a": "[REDACTED:k]", "b": "[REDACTED:k]", "n": 1 });
        assert_eq!(clean.json.as_ref(), Some(&expected));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&clean.body).unwrap(), expected, "{}", clean.body);
    }

    #[test]
    fn keys_hidden_deep_in_arrays_and_object_keys_are_redacted() {
        let redactor = redactor_for("abcd/efgh_1234");
        let body = r#"[{"x":[1,{"abcd\/efgh_1234":["abcd\/efgh_1234",null]}]},"plain"]"#;
        let clean = redact_response(&redactor, with_body(body));
        let expected = serde_json::json!([{ "x": [1, { "[REDACTED:k]": ["[REDACTED:k]", null] }] }, "plain"]);
        assert_eq!(clean.json, Some(expected));
        assert!(!json_has_secret(&redactor, clean.json.as_ref().unwrap()));
    }

    #[test]
    fn bodies_without_a_key_keep_their_exact_text() {
        let body = "{ \"a\" : \"x\\/y\",\n  \"n\": 1 }";
        let clean = redact_response(&redactor_for("abcd/efgh_1234"), with_body(body));
        assert_eq!(clean.body, body);
        assert_eq!(clean.json, Some(serde_json::json!({ "a": "x/y", "n": 1 })));
    }

    #[test]
    fn parse_json_only_for_json_looking_bodies() {
        assert!(parse_json(r#" {"a":1}"#).is_some());
        assert!(parse_json("[1]").is_some());
        assert!(parse_json("hello").is_none());
        assert!(parse_json("{broken").is_none());
    }
}
