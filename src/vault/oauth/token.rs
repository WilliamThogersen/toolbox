use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde_json::Value;
use ureq::Agent;
use url::form_urlencoded;

use super::OAuth;
use crate::cli::screen::{one_line, printable};
use crate::vault::SecretValue;

const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REPLY_BYTES: u64 = 1024 * 1024;
const MAX_ERROR_LEN: usize = 64;
const MAX_DESCRIPTION_LEN: usize = 200;

#[derive(Debug)]
pub struct Tokens {
    pub access: SecretValue,
    pub refresh: Option<SecretValue>,
    pub expires_in: Option<u64>,
    pub status: u16,
}

pub fn refresh(oauth: &OAuth, refresh_token: &SecretValue) -> Result<Tokens> {
    let form = [("grant_type", "refresh_token"), ("refresh_token", refresh_token.expose())];
    post(oauth, &form, &[refresh_token.expose()])
}

pub fn exchange(oauth: &OAuth, code: &str, redirect_uri: &str, verifier: &str) -> Result<Tokens> {
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", verifier),
    ];
    post(oauth, &form, &[code, verifier])
}

fn post(oauth: &OAuth, form: &[(&str, &str)], hidden: &[&str]) -> Result<Tokens> {
    let secret = oauth.client_secret.as_ref().map(SecretValue::expose);
    let client = [("client_id", oauth.client_id.as_str())].into_iter().chain(secret.map(|s| ("client_secret", s)));
    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form.iter().copied().chain(client))
        .finish();
    let agent: Agent = Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .proxy(None)
        .timeout_global(Some(TIMEOUT))
        .build()
        .into();
    let host = oauth.token_host();
    let mut response = agent
        .post(oauth.token_url.as_str())
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .send(body.as_bytes())
        .map_err(|err| anyhow!("could not reach the sign-in server {host}: {err}"))?;
    let status = response.status().as_u16();
    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_REPLY_BYTES)
        .read_to_vec()
        .with_context(|| format!("could not read the answer from {host}"))?;
    let hidden: Vec<&str> = hidden.iter().copied().chain(secret).collect();
    parse(status, &bytes, &hidden)
}

fn parse(status: u16, body: &[u8], hidden: &[&str]) -> Result<Tokens> {
    let reply: Value =
        serde_json::from_slice(body).map_err(|_| anyhow!("the sign-in server answered {status} without JSON"))?;
    if reply.get("error").is_some_and(|error| !error.is_null()) {
        bail!(refusal(status, &reply, hidden));
    }
    ensure!((200..300).contains(&status), "the sign-in server answered {status}");
    let access = reply
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the sign-in server's answer has no access_token"))?;
    let access = SecretValue::new(access.to_string()).context("the sign-in server's access token can't be used")?;
    let refresh = reply
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(|token| SecretValue::new(token.to_string()).context("the sign-in server's refresh token can't be used"))
        .transpose()?;
    let expires_in = match reply.get("expires_in") {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    };
    Ok(Tokens { access, refresh, expires_in, status })
}

fn refusal(status: u16, reply: &Value, hidden: &[&str]) -> String {
    let code = reply
        .get("error")
        .and_then(Value::as_str)
        .filter(|code| {
            code.len() <= MAX_ERROR_LEN && code.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        })
        .unwrap_or("an error");
    let description = reply
        .get("error_description")
        .and_then(Value::as_str)
        .filter(|text| !hidden.iter().any(|secret| !secret.is_empty() && text.contains(secret)))
        .map(|text| printable(&one_line(text)).chars().take(MAX_DESCRIPTION_LEN).collect::<String>());
    match description {
        Some(text) => format!("the sign-in server answered {status} with {code}: {text}"),
        None => format!("the sign-in server answered {status} with {code}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_reply_gives_access_refresh_and_lifetime() {
        let body = br#"{"access_token":"fake_access_123","refresh_token":"fake_refresh_123","expires_in":"3599","token_type":"Bearer"}"#;
        let tokens = parse(200, body, &[]).unwrap();
        assert_eq!(tokens.access.expose(), "fake_access_123");
        assert_eq!(tokens.refresh.as_ref().map(SecretValue::expose), Some("fake_refresh_123"));
        assert_eq!(tokens.expires_in, Some(3599));

        let bare = parse(200, br#"{"access_token":"fake_access_123","expires_in":60}"#, &[]).unwrap();
        assert!(bare.refresh.is_none());
        assert_eq!(bare.expires_in, Some(60));
    }

    #[test]
    fn refusals_say_why_without_echoing_secrets() {
        let err = parse(400, br#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#, &[])
            .unwrap_err()
            .to_string();
        assert_eq!(err, "the sign-in server answered 400 with invalid_grant: Token has been expired or revoked.");

        let echo = br#"{"error":"invalid_grant","error_description":"bad token fake_refresh_123"}"#;
        let err = parse(400, echo, &["fake_refresh_123"]).unwrap_err().to_string();
        assert_eq!(err, "the sign-in server answered 400 with invalid_grant");

        let github = br#"{"error":"bad_verification_code","error_description":"The code passed is incorrect\nor expired."}"#;
        let err = parse(200, github, &[]).unwrap_err().to_string();
        assert!(err.contains("bad_verification_code: The code passed is incorrect\\nor expired."), "{err}");

        let weird = br#"{"error":"<script>\u001b[2J","error_description":"\u001b[2Jhidden"}"#;
        let err = parse(400, weird, &[]).unwrap_err().to_string();
        assert!(err.contains("with an error: \\u{1b}[2Jhidden"), "{err}");
    }

    #[test]
    fn broken_replies_are_errors() {
        assert!(parse(200, b"access_token=x", &[]).unwrap_err().to_string().contains("without JSON"));
        assert!(parse(500, b"{}", &[]).unwrap_err().to_string().contains("answered 500"));
        assert!(parse(200, b"{}", &[]).unwrap_err().to_string().contains("no access_token"));
        assert!(parse(200, br#"{"access_token":"short"}"#, &[]).is_err());
    }
}
