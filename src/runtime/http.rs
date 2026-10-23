//! `http.*` for scripts, with vault injection and response redaction.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use mlua::{Lua, LuaSerdeExt, Table, Value};
use serde::{Deserialize, Serialize};
use ureq::http::{Request, Response};
use ureq::{Agent, AsSendBody, Body, Proxy};
use url::{Url, form_urlencoded};

use super::encoding::query_pairs;
use super::{seconds, ser_options};
use crate::manifest::Permissions;
use crate::vault::approval::Caller;
use crate::vault::inject::{Injector, Redactor, ensure_absent, mentions_vault};
use crate::vault::{VaultData, VaultStore};

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

/// The table passed to `http.request{...}`.
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
    /// Sent as `application/x-www-form-urlencoded`.
    #[serde(default)]
    pub form: Option<BTreeMap<String, serde_json::Value>>,
    /// Appended to the URL's query string.
    #[serde(default)]
    pub query: BTreeMap<String, serde_json::Value>,
    /// Seconds, instead of the default `TIMEOUT`.
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

/// Loads the vault on first use, so commands that never use a secret never touch the keychain.
struct LazyVault {
    store: Box<dyn VaultStore>,
    loaded: RefCell<Option<Rc<VaultData>>>,
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
            .map(|data| Redactor::new(data))
            .unwrap_or_default()
    }
}

pub struct HttpClient {
    allowed_hosts: Vec<String>,
    caller: Caller,
    vault: LazyVault,
    following: Agent,
    /// Used whenever a secret is attached. No redirects (they could carry the
    /// secret elsewhere) and no env proxy (HTTP_PROXY could point at an attacker).
    secret_safe: Agent,
}

impl HttpClient {
    pub fn new(perms: &Permissions, caller: Caller, store: Box<dyn VaultStore>) -> Self {
        Self {
            allowed_hosts: perms.http.iter().map(|h| h.to_ascii_lowercase()).collect(),
            caller,
            vault: LazyVault {
                store,
                loaded: RefCell::new(None),
            },
            following: agent(MAX_REDIRECTS, Proxy::try_from_env()),
            secret_safe: agent(0, None),
        }
    }

    pub fn send(&self, spec: RequestSpec) -> Result<ResponseData> {
        let mut url = Url::parse(&spec.url).with_context(|| format!("invalid url {:?}", spec.url))?;
        self.check_host(&url)?;
        ensure_absent("url", &spec.url)?;
        let query = query_pairs(&spec.options.query)?;
        let timeout = spec.options.timeout.map(seconds).transpose()?;
        let (body, content_type) = encode_body(&spec.options)?;
        ensure_absent("body", &String::from_utf8_lossy(&body))?;

        let mut headers: Vec<(String, String)> = spec.options.headers.into_iter().collect();
        if let Some(ct) = content_type
            && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            headers.push(("content-type".to_string(), ct.to_string()));
        }
        let uses_vault = headers
            .iter()
            .chain(&query)
            .any(|(k, v)| mentions_vault(k) || mentions_vault(v));
        let (headers, query, agent) = if uses_vault {
            let vault = self.vault.get()?;
            let injector = Injector {
                vault: &vault,
                caller: &self.caller,
                url: &url,
            };
            (injector.headers(&headers)?, injector.query(&query)?, &self.secret_safe)
        } else {
            (headers, query, &self.following)
        };
        append_query(&mut url, &query);

        let redactor = self.vault.redactor();
        let response = execute(agent, &spec.method, &url, &headers, body, timeout)
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        Ok(redact_response(&redactor, response))
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

fn agent(max_redirects: u32, proxy: Option<Proxy>) -> Agent {
    Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(max_redirects)
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

/// Appends `query = {...}` pairs (secrets already filled in) to whatever query the URL has.
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

/// Placeholders are checked before encoding: once escaped they would no longer be recognised.
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

fn execute(
    agent: &Agent,
    method: &str,
    url: &Url,
    headers: &[(String, String)],
    body: Vec<u8>,
    timeout: Option<Duration>,
) -> Result<ResponseData> {
    let builder = headers.iter().fold(
        ureq::http::Request::builder()
            .method(method.to_ascii_uppercase().as_str())
            .uri(url.as_str()),
        |builder, (name, value)| builder.header(name.as_str(), value.as_str()),
    );
    let mut response = if body.is_empty() {
        run(agent, builder.body(ureq::SendBody::none()).context("invalid request")?, timeout)
    } else {
        run(agent, builder.body(body).context("invalid request")?, timeout)
    }
    .map_err(|e| anyhow!("request to {} failed: {e}", url.host_str().unwrap_or("?")))?;

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

/// Scrubs secrets first, then parses JSON from the scrubbed text.
fn redact_response(redactor: &Redactor, response: ResponseData) -> ResponseData {
    let body = redactor.redact(&response.body);
    let headers = response
        .headers
        .into_iter()
        .map(|(name, value)| (name, redactor.redact(&value)))
        .collect();
    let json = parse_json(&body);
    ResponseData {
        status: response.status,
        headers,
        body,
        json,
    }
}

fn parse_json(body: &str) -> Option<serde_json::Value> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        serde_json::from_str(body).ok()
    } else {
        None
    }
}

pub fn install(lua: &Lua, client: Rc<HttpClient>) -> mlua::Result<()> {
    let http: Table = lua.create_table()?;
    let request_client = Rc::clone(&client);
    http.set(
        "request",
        lua.create_function(move |lua, spec: Value| {
            let raw: RawRequest = lua.from_value(spec)?;
            send_to_lua(lua, &request_client, raw.into())
        })?,
    )?;
    for method in SUGAR_METHODS {
        let method_client = Rc::clone(&client);
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

    fn client(http: &[&str], vault: &[&str]) -> HttpClient {
        let perms = Permissions {
            http: http.iter().map(|s| s.to_string()).collect(),
            vault: vault.iter().map(|s| s.to_string()).collect(),
            ..Permissions::default()
        };
        let caller = Caller {
            name: "t".into(),
            declared: perms.vault.clone(),
            fingerprint: "t".into(),
        };
        HttpClient::new(&perms, caller, Box::new(MemoryStore::new(VaultData::default())))
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
        assert!(in_query.unwrap_err().to_string().contains("tb self vault add github"));
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
        assert!(err.to_string().contains("tb self vault add github"));
    }

    #[test]
    fn timeout_option_limits_the_wait() {
        // Accepts connections into the backlog but never answers.
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

    #[test]
    fn parse_json_only_for_json_looking_bodies() {
        assert!(parse_json(r#" {"a":1}"#).is_some());
        assert!(parse_json("[1]").is_some());
        assert!(parse_json("hello").is_none());
        assert!(parse_json("{broken").is_none());
    }
}
