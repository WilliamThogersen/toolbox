//! `http.*` for scripts, with vault injection and response redaction.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use mlua::{Lua, LuaSerdeExt, Table, Value};
use serde::{Deserialize, Serialize};
use ureq::{Agent, Proxy};
use url::Url;

use super::ser_options;
use crate::manifest::Permissions;
use crate::vault::inject::{Redactor, ensure_absent, inject_headers, mentions_vault};
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
    declared_secrets: Vec<String>,
    vault: LazyVault,
    following: Agent,
    /// Used whenever a secret is attached. No redirects (they could carry the
    /// secret elsewhere) and no env proxy (HTTP_PROXY could point at an attacker).
    secret_safe: Agent,
}

impl HttpClient {
    pub fn new(perms: &Permissions, store: Box<dyn VaultStore>) -> Self {
        Self {
            allowed_hosts: perms.http.iter().map(|h| h.to_ascii_lowercase()).collect(),
            declared_secrets: perms.vault.clone(),
            vault: LazyVault {
                store,
                loaded: RefCell::new(None),
            },
            following: agent(MAX_REDIRECTS, Proxy::try_from_env()),
            secret_safe: agent(0, None),
        }
    }

    pub fn send(&self, spec: RequestSpec) -> Result<ResponseData> {
        let url = Url::parse(&spec.url).with_context(|| format!("invalid url {:?}", spec.url))?;
        self.check_host(&url)?;
        ensure_absent("url", &spec.url)?;
        let (body, content_type) = encode_body(&spec.options)?;
        ensure_absent("body", &String::from_utf8_lossy(&body))?;

        let mut headers: Vec<(String, String)> = spec.options.headers.into_iter().collect();
        if let Some(ct) = content_type
            && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            headers.push(("content-type".to_string(), ct.to_string()));
        }
        let uses_vault = headers.iter().any(|(k, v)| mentions_vault(k) || mentions_vault(v));
        let (headers, agent) = if uses_vault {
            let vault = self.vault.get()?;
            let injected = inject_headers(&headers, &url, &vault, &self.declared_secrets)?;
            (injected, &self.secret_safe)
        } else {
            (headers, &self.following)
        };

        let redactor = self.vault.redactor();
        let response = execute(agent, &spec.method, &url, &headers, body)
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
    match (&options.body, &options.json) {
        (Some(_), Some(_)) => Err(anyhow!("use either body or json, not both")),
        (Some(body), None) => Ok((body.clone().into_bytes(), None)),
        (None, Some(json)) => Ok((serde_json::to_vec(json)?, Some("application/json"))),
        (None, None) => Ok((Vec::new(), None)),
    }
}

fn execute(
    agent: &Agent,
    method: &str,
    url: &Url,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> Result<ResponseData> {
    let builder = headers.iter().fold(
        ureq::http::Request::builder()
            .method(method.to_ascii_uppercase().as_str())
            .uri(url.as_str()),
        |builder, (name, value)| builder.header(name.as_str(), value.as_str()),
    );
    let mut response = if body.is_empty() {
        agent.run(builder.body(ureq::SendBody::none()).context("invalid request")?)
    } else {
        agent.run(builder.body(body).context("invalid request")?)
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
        HttpClient::new(&perms, Box::new(MemoryStore::new(VaultData::default())))
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
    fn refuses_body_and_json_together() {
        let options = RequestOptions {
            body: Some("x".into()),
            json: Some(serde_json::json!({})),
            ..RequestOptions::default()
        };
        assert!(encode_body(&options).is_err());
    }

    #[test]
    fn missing_secret_is_reported_before_any_request() {
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".to_string(), "Bearer {{vault:github}}".to_string());
        let err = client(&["*"], &["github"])
            .send(spec("https://x.example/", RequestOptions { headers, ..RequestOptions::default() }))
            .unwrap_err();
        assert!(err.to_string().contains("tb vault add github"));
    }

    #[test]
    fn parse_json_only_for_json_looking_bodies() {
        assert!(parse_json(r#" {"a":1}"#).is_some());
        assert!(parse_json("[1]").is_some());
        assert!(parse_json("hello").is_none());
        assert!(parse_json("{broken").is_none());
    }
}
