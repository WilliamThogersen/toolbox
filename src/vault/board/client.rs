use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use ureq::http::Request;
use ureq::{Agent, SendBody};

use super::Connection;

const MAX_ANSWER_BYTES: u64 = 32 * 1024 * 1024;
const LIST_TIMEOUT: Duration = Duration::from_secs(30);
const PROXY_MARGIN: Duration = Duration::from_secs(10);
const SHOWN_ERROR_CHARS: usize = 300;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BoardSecret {
    pub name: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProxyRequest<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    pub query: &'a [(String, String)],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Debug)]
pub struct Proxied {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Deserialize)]
struct RawProxied {
    status: u16,
    #[serde(default)]
    headers: serde_json::Value,
    #[serde(default)]
    body: String,
}

#[derive(Serialize)]
struct Put<'a> {
    value: &'a str,
    allowed_hosts: &'a [String],
    methods: &'a [String],
    paths: &'a [String],
}

impl Connection {
    pub fn secrets(&self) -> Result<Vec<BoardSecret>> {
        let (status, bytes) = self.call("GET", "/api/v1/vault/secrets", None, LIST_TIMEOUT)?;
        ensure_ok(status, &bytes, "list the board's secrets")?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).context("the board's secret list is not JSON")?;
        let items = match value {
            serde_json::Value::Array(_) => value,
            serde_json::Value::Object(mut map) => map.remove("secrets").unwrap_or_default(),
            _ => bail!("the board's secret list has an unknown shape"),
        };
        serde_json::from_value(items).context("the board's secret list has an unknown shape")
    }

    pub fn put_secret(&self, name: &str, value: &str, hosts: &[String], methods: &[String], paths: &[String]) -> Result<()> {
        let body = serde_json::to_vec(&Put { value, allowed_hosts: hosts, methods, paths })?;
        let path = format!("/api/v1/secrets/{}", percent_encoding::utf8_percent_encode(name, NAME));
        let (status, bytes) = self.call("PUT", &path, Some(body), LIST_TIMEOUT)?;
        ensure_ok(status, &bytes, &format!("save {name:?} on the board"))
    }

    pub fn proxy(&self, request: &ProxyRequest) -> Result<Proxied> {
        let body = serde_json::to_vec(request)?;
        let wait = Duration::from_millis(request.timeout_ms) + PROXY_MARGIN;
        let (status, bytes) = self.call("POST", "/api/v1/vault/request", Some(body), wait)?;
        ensure_ok(status, &bytes, "send the request through the board")?;
        let raw: RawProxied = serde_json::from_slice(&bytes).context("the board's answer is not the expected JSON")?;
        let body = STANDARD.decode(raw.body.as_bytes()).context("the board's answer body is not base64")?;
        Ok(Proxied { status: raw.status, headers: header_map(&raw.headers), body })
    }

    fn call(&self, method: &str, path: &str, body: Option<Vec<u8>>, timeout: Duration) -> Result<(u16, Vec<u8>)> {
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .timeout_global(Some(timeout))
            .build()
            .into();
        let builder = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base()))
            .header("authorization", format!("Bearer {}", self.token()))
            .header("accept", "application/json");
        let mut response = match body {
            Some(bytes) => agent.run(builder.header("content-type", "application/json").body(bytes)?),
            None => agent.run(builder.body(SendBody::none())?),
        }
        .map_err(|e| anyhow!("could not reach the board {}: {e}", self.base()))?;
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER_BYTES)
            .read_to_vec()
            .context("could not read the board's answer")?;
        Ok((response.status().as_u16(), bytes))
    }
}

const NAME: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'/');

fn header_map(value: &serde_json::Value) -> BTreeMap<String, String> {
    let text = |value: &serde_json::Value| match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    let mut map = BTreeMap::new();
    match value {
        serde_json::Value::Object(object) => {
            for (name, value) in object {
                map.insert(name.clone(), text(value));
            }
        }
        serde_json::Value::Array(pairs) => {
            for pair in pairs {
                if let [name, value] = pair.as_array().map(Vec::as_slice).unwrap_or_default() {
                    map.entry(text(name)).and_modify(|have: &mut String| {
                        have.push_str(", ");
                        have.push_str(&text(value));
                    }).or_insert_with(|| text(value));
                }
            }
        }
        _ => {}
    }
    map
}

fn ensure_ok(status: u16, bytes: &[u8], what: &str) -> Result<()> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    let parsed: Option<serde_json::Value> = serde_json::from_slice(bytes).ok();
    let message = parsed
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(|error| error.as_str().map(str::to_string))
        .unwrap_or_else(|| String::from_utf8_lossy(bytes).into_owned());
    let shown: String = crate::cli::screen::printable(&message).chars().take(SHOWN_ERROR_CHARS).collect();
    bail!("the board refused to {what} (HTTP {status}): {shown}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_come_as_an_object_or_as_pairs() {
        let object = serde_json::json!({"content-type": "text/plain", "x-n": 3});
        assert_eq!(header_map(&object).get("x-n").map(String::as_str), Some("3"));
        let pairs = serde_json::json!([["set-cookie", "a=1"], ["set-cookie", "b=2"]]);
        assert_eq!(header_map(&pairs).get("set-cookie").map(String::as_str), Some("a=1, b=2"));
    }

    #[test]
    fn errors_show_the_boards_text() {
        let err = ensure_ok(403, br#"{"error":"secret \"x\" may not go to evil.test"}"#, "send").unwrap_err();
        assert!(err.to_string().contains("secret \"x\" may not go to evil.test"));
        assert!(ensure_ok(200, b"{}", "send").is_ok());
    }
}
