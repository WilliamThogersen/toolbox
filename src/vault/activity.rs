use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;

use super::log::{Filter, OLD_LOG_FILE, matches};
use crate::cli::screen::{one_line, printable};

const POLL: Duration = Duration::from_millis(500);
const MAX_READ_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FIELD_CHARS: usize = 160;
const EVENT_WIDTH: usize = 10;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Json,
    Plain,
    Color,
}

pub fn render(entry: &Value, style: Style) -> String {
    match style {
        Style::Json => entry.to_string(),
        Style::Plain | Style::Color => line(entry, style == Style::Color),
    }
}

fn line(entry: &Value, color: bool) -> String {
    let event = text(&entry["event"]);
    let time = text(&entry["time"]).replacen('T', " ", 1).chars().take(19).collect::<String>();
    let padded = format!("{event:<EVENT_WIDTH$}");
    let (time, event) = if color {
        (paint("2", &time), paint(tone(entry), &padded))
    } else {
        (time, padded)
    };
    let who = who(entry);
    let who = if who.is_empty() { String::new() } else { format!("  [{who}]") };
    format!("{time}  {event}{}{who}", what(entry))
}

fn paint(code: &str, text: &str) -> String {
    format!("\u{1b}[{code}m{text}\u{1b}[0m")
}

fn tone(entry: &Value) -> &'static str {
    match entry["event"].as_str() {
        Some("used") if entry.pointer("/outcome/status").and_then(Value::as_u64).is_some_and(|s| (200..400).contains(&s)) => {
            "32"
        }
        Some("used" | "requested") => "33",
        Some("refused" | "declined" | "removed" | "revoked") => "31",
        Some("refreshed") if entry.pointer("/outcome/failed").is_some_and(Value::is_string) => "31",
        Some("added" | "allowed" | "signed_in") => "36",
        _ => "0",
    }
}

fn what(entry: &Value) -> String {
    let (key, command) = (text(&entry["key"]), text(&entry["command"]));
    match entry["event"].as_str().unwrap_or_default() {
        "requested" => format!("{key} for {}: {}", list(&entry["hosts"]), text(&entry["why"])),
        "added" => format!("{key} for {}{}", list(&entry["hosts"]), limits(entry)),
        "signed_in" => format!("{key} at {} for {}", text(&entry["provider"]), list(&entry["hosts"])),
        "allowed" | "declined" | "revoked" => format!("{command} to use {key}"),
        "removed" => key,
        "refreshed" => format!("{key} for {command} at {} {}", text(&entry["host"]), outcome(&entry["outcome"])),
        "used" => {
            let confirmed = if entry["confirmed"] == true { " (confirmed with Touch ID)" } else { "" };
            format!("{command} with {} {} {}{confirmed}", list(&entry["keys"]), request(&entry["request"]), outcome(&entry["outcome"]))
        }
        "refused" => format!("{command} with {} {}: {}", list(&entry["keys"]), request(&entry["request"]), text(&entry["reason"])),
        _ => String::new(),
    }
}

fn limits(entry: &Value) -> String {
    let parts: Vec<String> = [("query", "query_params"), ("only", "methods"), ("paths", "paths"), ("asks for", "confirm")]
        .iter()
        .filter(|(_, field)| entry[*field].as_array().is_some_and(|items| !items.is_empty()))
        .map(|(label, field)| format!("{label} {}", list(&entry[*field])))
        .collect();
    if parts.is_empty() { String::new() } else { format!(" ({})", parts.join("; ")) }
}

fn request(request: &Value) -> String {
    format!("{} {}{}", text(&request["method"]), text(&request["host"]), text(&request["path"]))
}

fn outcome(outcome: &Value) -> String {
    match (outcome["status"].as_u64(), outcome.get("failed")) {
        (Some(status), _) => format!("-> {status}"),
        (None, Some(failed)) => format!("-> failed: {}", text(failed)),
        (None, None) => String::new(),
    }
}

fn who(entry: &Value) -> String {
    let by: Vec<&str> = entry["by"].as_array().map(|by| by.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    let through_mcp = by.first().is_some_and(|first| is_toolbox(first));
    let program = by.iter().find(|path| !is_toolbox(path)).map(|path| short_name(path)).unwrap_or_default();
    let terminal = if entry["terminal"] == true { ", terminal" } else { "" };
    match (program.is_empty(), through_mcp) {
        (true, _) => String::new(),
        (false, true) => format!("{} via MCP{terminal}", clean(&program)),
        (false, false) => format!("{}{terminal}", clean(&program)),
    }
}

fn is_toolbox(path: &str) -> bool {
    matches!(Path::new(path).file_name().and_then(|n| n.to_str()), Some("toolbox" | "tb"))
}

fn short_name(path: &str) -> String {
    let path = Path::new(path);
    let parent = path.parent();
    let name = match parent.and_then(Path::file_name).and_then(|n| n.to_str()) {
        Some("versions") => parent.and_then(Path::parent).and_then(Path::file_name),
        _ => path.file_name(),
    };
    name.and_then(|n| n.to_str()).unwrap_or_default().to_string()
}

fn list(items: &Value) -> String {
    let items: Vec<String> = items.as_array().map(|items| items.iter().map(text).collect()).unwrap_or_default();
    items.join(", ")
}

fn text(value: &Value) -> String {
    let raw = match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    clean(&raw)
}

fn clean(raw: &str) -> String {
    let shown = printable(&one_line(raw));
    if shown.chars().count() > MAX_FIELD_CHARS {
        format!("{}...", shown.chars().take(MAX_FIELD_CHARS).collect::<String>())
    } else {
        shown
    }
}

#[derive(Clone, Copy)]
struct Spot {
    inode: u64,
    offset: u64,
}

pub struct Follower<'a> {
    pub path: PathBuf,
    pub filter: &'a Filter<'a>,
    pub style: Style,
}

impl Follower<'_> {
    pub fn start(&self) -> Option<(u64, u64)> {
        fs::metadata(&self.path).ok().map(|meta| (meta.ino(), meta.len()))
    }

    pub fn run(&self, start: Option<(u64, u64)>, out: &mut dyn FnMut(&str) -> Result<bool>) -> Result<()> {
        let mut spot = start.map(|(inode, offset)| Spot { inode, offset });
        loop {
            thread::sleep(POLL);
            let Ok(meta) = fs::metadata(&self.path) else { continue };
            let next = match &spot {
                Some(seen) if seen.inode == meta.ino() && seen.offset <= meta.len() => *seen,
                Some(seen) => {
                    if !self.emit_rest(&self.path.with_file_name(OLD_LOG_FILE), seen, out)? {
                        return Ok(());
                    }
                    Spot { inode: meta.ino(), offset: 0 }
                }
                None => Spot { inode: meta.ino(), offset: 0 },
            };
            let (offset, open) = self.emit_from(&self.path, &next, out)?;
            if !open {
                return Ok(());
            }
            spot = Some(Spot { inode: next.inode, offset });
        }
    }

    fn emit_rest(&self, rotated: &Path, seen: &Spot, out: &mut dyn FnMut(&str) -> Result<bool>) -> Result<bool> {
        match fs::metadata(rotated) {
            Ok(meta) if meta.ino() == seen.inode => Ok(self.emit_from(rotated, seen, out)?.1),
            _ => Ok(true),
        }
    }

    fn emit_from(&self, path: &Path, spot: &Spot, out: &mut dyn FnMut(&str) -> Result<bool>) -> Result<(u64, bool)> {
        let opened = OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path);
        let Some(mut file) = opened.ok().filter(|file| file.metadata().is_ok_and(|meta| meta.is_file())) else {
            return Ok((spot.offset, true));
        };
        file.seek(SeekFrom::Start(spot.offset))?;
        let mut bytes = Vec::new();
        file.take(MAX_READ_BYTES).read_to_end(&mut bytes).with_context(|| format!("could not read {}", path.display()))?;
        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |at| at + 1);
        let fresh = bytes.get(..complete).unwrap_or_default();
        let entries = String::from_utf8_lossy(fresh)
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|entry| matches(entry, self.filter))
            .collect::<Vec<_>>();
        for entry in entries {
            if !out(&render(&entry, self.style))? {
                return Ok((spot.offset, false));
            }
        }
        Ok((spot.offset + u64::try_from(complete)?, true))
    }
}

pub fn print_line(text: &str) -> Result<bool> {
    let mut out = io::stdout().lock();
    match writeln!(out, "{text}").and_then(|()| out.flush()) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn uses_read_as_one_line() {
        let entry = json!({
            "time": "2026-10-23T09:12:03+02:00",
            "event": "used",
            "keys": ["pagespeed"],
            "command": "lighthouse",
            "request": { "method": "GET", "host": "www.googleapis.com", "path": "/pagespeedonline/v5/runPagespeed" },
            "outcome": { "status": 200 },
            "by": ["/opt/homebrew/bin/toolbox", "/Users/me/.local/share/claude/versions/2.1.308", "/bin/zsh"],
            "terminal": false
        });
        assert_eq!(
            render(&entry, Style::Plain),
            "2026-10-23 09:12:03  used      lighthouse with pagespeed GET www.googleapis.com/pagespeedonline/v5/runPagespeed -> 200  [claude via MCP]"
        );
        let colored = render(&entry, Style::Color);
        assert!(colored.contains("\u{1b}[32mused      \u{1b}[0m"), "{colored:?}");
        assert_eq!(render(&entry, Style::Json), entry.to_string());
    }

    #[test]
    fn every_event_reads_naturally() {
        let shown = |entry: Value| render(&entry, Style::Plain).split_once("  ").map(|(_, rest)| rest.to_string()).unwrap();
        let by = json!(["/bin/zsh", "/usr/bin/login"]);
        assert_eq!(
            shown(json!({ "event": "allowed", "key": "github", "command": "stars", "by": by, "terminal": true })),
            "allowed   stars to use github  [zsh, terminal]"
        );
        assert_eq!(
            shown(json!({ "event": "added", "key": "github", "hosts": ["api.github.com"], "query_params": [], "methods": ["GET"], "confirm": ["writes"] })),
            "added     github for api.github.com (only GET; asks for writes)"
        );
        assert_eq!(
            shown(json!({ "event": "refused", "keys": ["github"], "command": "stars", "request": { "method": "POST", "host": "x.com", "path": "/" }, "reason": "nope" })),
            "refused   stars with github POST x.com/: nope"
        );
        assert_eq!(
            shown(json!({ "event": "used", "keys": ["mail"], "command": "send", "request": { "method": "POST", "host": "x.com", "path": "/send" }, "outcome": { "status": 202 }, "confirmed": true })),
            "used      send with mail POST x.com/send -> 202 (confirmed with Touch ID)"
        );
        assert_eq!(
            shown(json!({ "event": "refreshed", "key": "google", "command": "mail", "host": "oauth2.googleapis.com", "outcome": { "failed": "invalid_grant" } })),
            "refreshed google for mail at oauth2.googleapis.com -> failed: invalid_grant"
        );
        assert_eq!(
            shown(json!({ "event": "signed_in", "key": "google", "provider": "accounts.google.com", "hosts": ["gmail.googleapis.com"] })),
            "signed_in google at accounts.google.com for gmail.googleapis.com"
        );
    }

    #[test]
    fn following_picks_up_new_entries_across_a_rotation() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault-log.jsonl");
        let entry = |key: &str| format!("{}\n", json!({ "event": "removed", "key": key }));
        fs::write(&path, entry("one")).unwrap();
        let filter = Filter { key: None, command: None, limit: 10 };
        let follower = Follower { path: path.clone(), filter: &filter, style: Style::Json };
        let start = follower.start();

        fs::write(&path, entry("one") + &entry("two") + r#"{"event":"removed","key":"half"#).unwrap();
        fs::rename(&path, path.with_file_name(OLD_LOG_FILE)).unwrap();
        fs::write(&path, entry("three")).unwrap();
        let mut seen = Vec::new();
        follower
            .run(start, &mut |line| {
                seen.push(serde_json::from_str::<Value>(line).unwrap()["key"].as_str().unwrap().to_string());
                Ok(seen.len() < 2)
            })
            .unwrap();
        assert_eq!(seen, ["two", "three"], "the end of the rotated file comes first, a half-written line never");
    }

    #[test]
    fn text_from_the_file_cannot_drive_the_terminal() {
        let entry = json!({ "event": "removed\u{1b}[2J", "key": "x\u{1b}]0;title\u{7}\ny\u{202e}z", "time": "2026\r" });
        let shown = render(&entry, Style::Color);
        let after_paint = shown.replace("\u{1b}[2m", "").replace("\u{1b}[0m", "");
        assert!(!after_paint.contains('\u{1b}') && !shown.contains('\n') && !shown.contains('\r'), "{shown:?}");
        assert!(!shown.contains('\u{202e}'), "{shown:?}");
        let long = json!({ "event": "removed", "key": "k".repeat(500) });
        assert!(render(&long, Style::Plain).len() < 300);
    }
}
