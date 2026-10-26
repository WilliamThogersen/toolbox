use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use hmac::{Hmac, KeyInit, Mac};
use mlua::{Lua, LuaSerdeExt, LuaString, Table, Value};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode, percent_encode};
use sha2::{Digest, Sha256};
use url::form_urlencoded;

use super::lua_error;
use crate::vault::inject::mentions_vault;

const STANDARD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
const URL_SAFE: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

const URL_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

pub fn install(lua: &Lua) -> mlua::Result<()> {
    install_base64(lua)?;
    install_url(lua)?;
    install_hash(lua)
}

fn refuse_placeholder(what: &str, data: &[u8]) -> Result<()> {
    if mentions_vault(&String::from_utf8_lossy(data)) {
        bail!(
            "{what} got a vault placeholder. Scripts never see keys, so placeholders only work directly in http header values and `query` parameters. For Basic auth, use vault(\"name\", \"base64\") on a key stored as user:password"
        );
    }
    Ok(())
}

fn install_base64(lua: &Lua) -> mlua::Result<()> {
    let table = lua.create_table()?;
    table.set(
        "encode",
        lua.create_function(|_, (data, variant): (LuaString, Option<String>)| {
            let bytes = data.as_bytes();
            refuse_placeholder("base64.encode", &bytes).map_err(lua_error)?;
            Ok(engine(variant.as_deref()).map_err(lua_error)?.encode(&*bytes))
        })?,
    )?;
    table.set(
        "decode",
        lua.create_function(|lua, (text, variant): (String, Option<String>)| {
            let bytes = engine(variant.as_deref())
                .map_err(lua_error)?
                .decode(text.trim())
                .map_err(|e| mlua::Error::runtime(format!("invalid base64: {e}")))?;
            lua.create_string(bytes)
        })?,
    )?;
    lua.globals().set("base64", table)
}

fn engine(variant: Option<&str>) -> Result<&'static GeneralPurpose> {
    match variant {
        None | Some("standard") => Ok(&STANDARD),
        Some("url") => Ok(&URL_SAFE),
        Some(other) => bail!("base64 variant must be \"standard\" or \"url\", not {other:?}"),
    }
}

fn install_url(lua: &Lua) -> mlua::Result<()> {
    let table = lua.create_table()?;
    table.set(
        "encode",
        lua.create_function(|_, text: LuaString| {
            let bytes = text.as_bytes();
            refuse_placeholder("url.encode", &bytes).map_err(lua_error)?;
            Ok(percent_encode(&bytes, URL_COMPONENT).to_string())
        })?,
    )?;
    table.set(
        "decode",
        lua.create_function(|lua, text: LuaString| {
            let decoded: Vec<u8> = percent_decode(&text.as_bytes()).collect();
            lua.create_string(decoded)
        })?,
    )?;
    table.set(
        "query",
        lua.create_function(|lua, params: Table| {
            let params: BTreeMap<String, serde_json::Value> = lua.from_value(Value::Table(params))?;
            let pairs = query_pairs(&params).map_err(lua_error)?;
            Ok(form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish())
        })?,
    )?;
    lua.globals().set("url", table)
}

pub fn query_pairs(params: &BTreeMap<String, serde_json::Value>) -> Result<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for (key, value) in params {
        match value {
            serde_json::Value::Array(items) => {
                for item in items {
                    pairs.push((key.clone(), scalar(key, item)?));
                }
            }
            other => pairs.push((key.clone(), scalar(key, other)?)),
        }
    }
    Ok(pairs)
}

fn scalar(key: &str, value: &serde_json::Value) -> Result<String> {
    match value {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        _ => Err(anyhow!(
            "{key:?} must be a string, number, boolean or a list of those"
        )),
    }
}

fn install_hash(lua: &Lua) -> mlua::Result<()> {
    let table = lua.create_table()?;
    table.set(
        "sha256",
        lua.create_function(|lua, (data, output): (LuaString, Option<String>)| {
            let bytes = data.as_bytes();
            refuse_placeholder("hash.sha256", &bytes).map_err(lua_error)?;
            render(lua, &Sha256::digest(&*bytes), output.as_deref())
        })?,
    )?;
    table.set(
        "hmac_sha256",
        lua.create_function(
            |lua, (key, data, output): (LuaString, LuaString, Option<String>)| {
                let (key, data) = (key.as_bytes(), data.as_bytes());
                refuse_placeholder("hash.hmac_sha256", &key).map_err(lua_error)?;
                refuse_placeholder("hash.hmac_sha256", &data).map_err(lua_error)?;
                let mut mac = Hmac::<Sha256>::new_from_slice(&key)
                    .map_err(|e| mlua::Error::runtime(format!("invalid hmac key: {e}")))?;
                mac.update(&data);
                render(lua, &mac.finalize().into_bytes(), output.as_deref())
            },
        )?,
    )?;
    lua.globals().set("hash", table)
}

fn render(lua: &Lua, digest: &[u8], output: Option<&str>) -> mlua::Result<LuaString> {
    match output.unwrap_or("hex") {
        "hex" => lua.create_string(digest.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().concat()),
        "base64" => lua.create_string(STANDARD.encode(digest)),
        "raw" => lua.create_string(digest),
        other => Err(mlua::Error::runtime(format!(
            "hash output must be \"hex\", \"base64\" or \"raw\", not {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::sandbox::new_lua;

    fn lua() -> Lua {
        let lua = new_lua().unwrap();
        install(&lua).unwrap();
        lua
    }

    fn eval(code: &str) -> String {
        lua().load(code).eval().unwrap()
    }

    fn err(code: &str) -> String {
        lua().load(code).exec().unwrap_err().to_string()
    }

    #[test]
    fn base64_round_trips_text_and_bytes() {
        assert_eq!(eval(r#"return base64.encode("hi there")"#), "aGkgdGhlcmU=");
        assert_eq!(eval(r#"return base64.decode("aGkgdGhlcmU=")"#), "hi there");
        assert_eq!(eval(r#"return base64.decode("aGkgdGhlcmU")"#), "hi there");
        assert_eq!(eval(r#"return base64.encode("\255\254?", "url")"#), "__4_");
        assert_eq!(eval(r#"return base64.decode("__4_", "url") == "\255\254?" and "same" or "diff""#), "same");
        assert!(err(r#"base64.decode("!!!")"#).contains("invalid base64"));
        assert!(err(r#"base64.encode("x", "hex")"#).contains("variant"));
    }

    #[test]
    fn url_encodes_components_and_queries() {
        assert_eq!(eval(r#"return url.encode("a b/c?d=é~")"#), "a%20b%2Fc%3Fd%3D%C3%A9~");
        assert_eq!(eval(r#"return url.decode("a%20b%2Fc")"#), "a b/c");
        assert_eq!(
            eval(r#"return url.query({ q = "a b&c", page = 2, tag = {"x", "y"}, on = true })"#),
            "on=true&page=2&q=a+b%26c&tag=x&tag=y"
        );
        assert!(err(r"url.query({ nested = { a = 1 } })").contains("must be a string"));
    }

    #[test]
    fn hashes_match_known_values() {
        assert_eq!(
            eval(r#"return hash.sha256("abc")"#),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            eval(r#"return hash.hmac_sha256("key", "The quick brown fox jumps over the lazy dog")"#),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
        assert_eq!(eval(r#"return hash.sha256("abc", "base64")"#), "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");
        assert_eq!(eval(r#"return tostring(#hash.sha256("abc", "raw"))"#), "32");
    }

    #[test]
    fn vault_placeholders_are_refused() {
        for code in [
            r#"base64.encode("user:{{vault:github}}")"#,
            r#"url.encode("{{vault:github}}")"#,
            r#"hash.sha256("{{vault:github}}")"#,
            r#"hash.hmac_sha256("{{vault:github}}", "data")"#,
        ] {
            assert!(err(code).contains("only work directly in http header values"), "{code}");
        }
    }
}
