//! `time.*` for scripts: the clock, formatting, parsing and sleeping. Times are
//! seconds since 1970 (UTC) as numbers with millisecond precision.

use std::fmt::Write;
use std::thread;

use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use mlua::Lua;

use super::{lua_error, seconds};

const UTC_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";
const LOCAL_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%:z";
const DATE_FORMAT: &str = "%Y-%m-%d";

pub fn install(lua: &Lua) -> mlua::Result<()> {
    let time = lua.create_table()?;
    time.set("now", lua.create_function(|_, ()| Ok(now()))?)?;
    time.set(
        "format",
        lua.create_function(
            |_, (ts, fmt, zone): (Option<f64>, Option<String>, Option<String>)| {
                format(ts.unwrap_or_else(now), fmt.as_deref(), zone.as_deref()).map_err(lua_error)
            },
        )?,
    )?;
    time.set(
        "parse",
        lua.create_function(|_, (text, fmt): (String, Option<String>)| {
            parse(&text, fmt.as_deref()).map_err(lua_error)
        })?,
    )?;
    time.set(
        "sleep",
        lua.create_function(|_, secs: f64| {
            thread::sleep(seconds(secs).map_err(lua_error)?);
            Ok(())
        })?,
    )?;
    lua.globals().set("time", time)
}

fn now() -> f64 {
    to_seconds(Utc::now())
}

fn to_seconds(t: DateTime<Utc>) -> f64 {
    t.timestamp_millis() as f64 / 1000.0
}

/// strftime-style `fmt` (default ISO 8601) in `"utc"` (default) or `"local"` time.
fn format(ts: f64, fmt: Option<&str>, zone: Option<&str>) -> Result<String> {
    let millis = (ts * 1000.0).round();
    let utc = (ts.is_finite() && millis.abs() < i64::MAX as f64)
        .then(|| DateTime::<Utc>::from_timestamp_millis(millis as i64))
        .flatten()
        .ok_or_else(|| anyhow!("{ts} is not a time toolbox can format"))?;
    let mut out = String::new();
    let written = match zone.unwrap_or("utc") {
        "utc" => write!(out, "{}", utc.format(fmt.unwrap_or(UTC_FORMAT))),
        "local" => write!(out, "{}", utc.with_timezone(&Local).format(fmt.unwrap_or(LOCAL_FORMAT))),
        other => bail!("zone must be \"utc\" or \"local\", not {other:?}"),
    };
    written.map_err(|_| anyhow!("invalid time format {:?}", fmt.unwrap_or_default()))?;
    Ok(out)
}

/// Without `fmt`: RFC 3339 (`2026-10-22T09:30:00Z`), RFC 2822 (HTTP dates) or a plain
/// `2026-10-22`. With `fmt`: strftime-style; a time without a zone is taken as UTC.
fn parse(text: &str, fmt: Option<&str>) -> Result<f64> {
    let parsed = match fmt {
        Some(fmt) => parse_with(text, fmt),
        None => DateTime::parse_from_rfc3339(text)
            .or_else(|_| DateTime::parse_from_rfc2822(text))
            .map(|t| t.to_utc())
            .or_else(|_| parse_with(text, DATE_FORMAT))
            .map_err(|_| {
                anyhow!("could not parse {text:?}: expected a date like 2026-10-22T09:30:00Z, or pass a format")
            }),
    }?;
    Ok(to_seconds(parsed))
}

fn parse_with(text: &str, fmt: &str) -> Result<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_str(text, fmt) {
        return Ok(t.to_utc());
    }
    if let Ok(t) = NaiveDateTime::parse_from_str(text, fmt) {
        return Ok(t.and_utc());
    }
    NaiveDate::parse_from_str(text, fmt)
        .map(|d| d.and_time(NaiveTime::MIN).and_utc())
        .map_err(|e| anyhow!("could not parse {text:?} with format {fmt:?}: {e}"))
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

    #[test]
    fn now_is_seconds_since_1970() {
        let now: f64 = lua().load("return time.now()").eval().unwrap();
        assert!(now > 1_700_000_000.0 && now < 4_000_000_000.0, "{now}");
    }

    #[test]
    fn formats_and_parses_round_trip() {
        let out: String = lua()
            .load(r#"
                local t = time.parse("2026-10-22T09:30:00+02:00")
                return t .. " " .. time.format(t) .. " " .. time.format(t, "%d/%m/%Y %H:%M")
            "#)
            .eval()
            .unwrap();
        assert_eq!(out, "1792654200.0 2026-10-22T07:30:00Z 22/10/2026 07:30");
    }

    #[test]
    fn parses_common_shapes() {
        assert_eq!(parse("2026-10-22", None).unwrap(), 1792627200.0);
        assert_eq!(parse("Thu, 22 Oct 2026 00:00:00 GMT", None).unwrap(), 1792627200.0);
        assert_eq!(parse("22.10.2026 01:00", Some("%d.%m.%Y %H:%M")).unwrap(), 1792630800.0);
        assert_eq!(parse("2026-10-22T00:00:00.250Z", None).unwrap(), 1792627200.25);
        assert!(parse("yesterday", None).unwrap_err().to_string().contains("pass a format"));
    }

    #[test]
    fn bad_inputs_are_errors() {
        let lua = lua();
        let zone = lua.load(r#"time.format(0, nil, "mars")"#).exec().unwrap_err();
        assert!(zone.to_string().contains("\"utc\" or \"local\""), "{zone}");
        let fmt = lua.load(r#"time.format(0, "%Q")"#).exec().unwrap_err();
        assert!(fmt.to_string().contains("invalid time format"), "{fmt}");
        let huge = lua.load(r#"time.format(1e300)"#).exec().unwrap_err();
        assert!(huge.to_string().contains("not a time"), "{huge}");
        let sleep = lua.load(r#"time.sleep(-1)"#).exec().unwrap_err();
        assert!(sleep.to_string().contains("not a valid number of seconds"), "{sleep}");
    }

    #[test]
    fn local_zone_has_an_offset() {
        let out: String = lua().load(r#"return time.format(0, nil, "local")"#).eval().unwrap();
        assert!(out.starts_with("19"), "{out}");
        assert!(out.contains('+') || out.contains('-'), "{out}");
    }
}
