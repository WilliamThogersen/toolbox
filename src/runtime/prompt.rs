use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};

use anyhow::{Result, anyhow, bail, ensure};
use mlua::Lua;

use super::api::needs_flag;
use super::lua_error;
use crate::cli::screen::{one_line, printable};

const MAX_ANSWER_BYTES: u64 = 4096;
const MAX_TRIES: usize = 3;
const MAX_CHOICES: usize = 100;
const PLAIN_TEXT: &str = "\x1b[0m\x1b(B\x0f";

pub trait Asker {
    fn ask(&mut self, text: &str) -> Result<String>;
}

pub struct DevTty;

impl Asker for DevTty {
    fn ask(&mut self, text: &str) -> Result<String> {
        let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty").map_err(|_| {
            anyhow!("prompt needs a person at a terminal, and this run has none. Take the answer as an arg instead")
        })?;
        write!(tty, "{PLAIN_TEXT}\n{text}")?;
        tty.flush()?;
        let mut answer = String::new();
        BufReader::new(&tty).take(MAX_ANSWER_BYTES + 1).read_line(&mut answer)?;
        ensure!(answer.len() as u64 <= MAX_ANSWER_BYTES, "the answer is longer than {MAX_ANSWER_BYTES} bytes");
        Ok(answer.trim().to_string())
    }
}

pub fn install(lua: &Lua, allowed: bool, label: &str) -> mlua::Result<()> {
    let prompt = lua.create_table()?;
    let who = label.to_string();
    prompt.set(
        "ask",
        lua.create_function(move |_, (question, default): (String, Option<String>)| {
            permitted(allowed, "prompt.ask")?;
            ask(&mut DevTty, &who, &question, default.as_deref()).map_err(lua_error)
        })?,
    )?;
    let who = label.to_string();
    prompt.set(
        "confirm",
        lua.create_function(move |_, (question, default): (String, Option<bool>)| {
            permitted(allowed, "prompt.confirm")?;
            confirm(&mut DevTty, &who, &question, default.unwrap_or(false)).map_err(lua_error)
        })?,
    )?;
    let who = label.to_string();
    prompt.set(
        "choose",
        lua.create_function(move |_, (question, options, default): (String, Vec<String>, Option<String>)| {
            permitted(allowed, "prompt.choose")?;
            choose(&mut DevTty, &who, &question, &options, default.as_deref()).map_err(lua_error)
        })?,
    )?;
    lua.globals().set("prompt", prompt)
}

fn permitted(allowed: bool, what: &str) -> mlua::Result<()> {
    if allowed { Ok(()) } else { Err(needs_flag("terminal", what)) }
}

fn shown(label: &str, text: &str) -> String {
    printable(&one_line(&format!("{label} asks: {text}")))
}

pub fn ask(asker: &mut dyn Asker, label: &str, question: &str, default: Option<&str>) -> Result<String> {
    let hint = default.map(|value| format!(" [{value}]")).unwrap_or_default();
    let answer = asker.ask(&format!("{} ", shown(label, &format!("{question}{hint}"))))?;
    Ok(match (answer.is_empty(), default) {
        (true, Some(value)) => value.to_string(),
        _ => answer,
    })
}

pub fn confirm(asker: &mut dyn Asker, label: &str, question: &str, default: bool) -> Result<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    let text = format!("{} ", shown(label, &format!("{question} {hint}")));
    for attempt in 0..MAX_TRIES {
        let again = if attempt == 0 { "" } else { "  answer y or n\n" };
        match asker.ask(&format!("{again}{text}"))?.to_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => {}
        }
    }
    bail!("no yes or no after {MAX_TRIES} answers")
}

pub fn choose(asker: &mut dyn Asker, label: &str, question: &str, options: &[String], default: Option<&str>) -> Result<String> {
    ensure!(
        (1..=MAX_CHOICES).contains(&options.len()),
        "prompt.choose takes 1 to {MAX_CHOICES} options, not {}",
        options.len()
    );
    if let Some(value) = default {
        ensure!(options.iter().any(|option| option == value), "the default {value:?} is not one of the options");
    }
    let listed: Vec<String> = options
        .iter()
        .enumerate()
        .map(|(at, option)| format!("  {}) {}", at + 1, printable(&one_line(option))))
        .collect();
    let hint = match default {
        Some(value) => format!("[1-{}, Enter = {value}]", options.len()),
        None => format!("[1-{}]", options.len()),
    };
    let text = format!("{}\n{} ", listed.join("\n"), shown(label, &format!("{question} {hint}")));
    for _ in 0..MAX_TRIES {
        let answer = asker.ask(&text)?;
        if let (true, Some(value)) = (answer.is_empty(), default) {
            return Ok(value.to_string());
        }
        let by_number = answer.parse::<usize>().ok().and_then(|n| n.checked_sub(1)).and_then(|at| options.get(at));
        if let Some(picked) = by_number.or_else(|| options.iter().find(|option| **option == answer)) {
            return Ok(picked.clone());
        }
    }
    bail!("no valid choice after {MAX_TRIES} answers")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scripted {
        answers: Vec<&'static str>,
        shown: Vec<String>,
    }

    impl Scripted {
        fn new(answers: &[&'static str]) -> Self {
            Self { answers: answers.iter().rev().copied().collect(), shown: Vec::new() }
        }
    }

    impl Asker for Scripted {
        fn ask(&mut self, text: &str) -> Result<String> {
            self.shown.push(text.to_string());
            Ok(self.answers.pop().unwrap_or("").to_string())
        }
    }

    #[test]
    fn ask_names_the_command_and_falls_back_to_the_default() {
        let mut asker = Scripted::new(&["", " bo "]);
        assert_eq!(ask(&mut asker, "notes add", "Title?", Some("today")).unwrap(), "today");
        assert_eq!(asker.shown[0], "notes add asks: Title? [today] ");
        assert_eq!(ask(&mut asker, "notes add", "Title?", None).unwrap(), " bo ");
    }

    #[test]
    fn confirm_takes_yes_no_or_the_default_and_asks_again() {
        assert!(confirm(&mut Scripted::new(&["Y"]), "x", "Sure?", false).unwrap());
        assert!(!confirm(&mut Scripted::new(&["no"]), "x", "Sure?", true).unwrap());
        assert!(confirm(&mut Scripted::new(&[""]), "x", "Sure?", true).unwrap());
        let mut asker = Scripted::new(&["maybe", "y"]);
        assert!(confirm(&mut asker, "x", "Sure?", false).unwrap());
        assert_eq!(asker.shown[1], "  answer y or n\nx asks: Sure? [y/N] ");
        let err = confirm(&mut Scripted::new(&["a", "b", "c"]), "x", "Sure?", false).unwrap_err();
        assert!(err.to_string().contains("no yes or no after 3"), "{err}");
    }

    #[test]
    fn choose_takes_a_number_a_name_or_the_default() {
        let options = vec!["8.2".to_string(), "8.3".to_string()];
        let mut asker = Scripted::new(&["2"]);
        assert_eq!(choose(&mut asker, "x", "PHP?", &options, None).unwrap(), "8.3");
        assert_eq!(asker.shown[0], "  1) 8.2\n  2) 8.3\nx asks: PHP? [1-2] ");
        assert_eq!(choose(&mut Scripted::new(&["8.2"]), "x", "PHP?", &options, None).unwrap(), "8.2");
        assert_eq!(choose(&mut Scripted::new(&[""]), "x", "PHP?", &options, Some("8.3")).unwrap(), "8.3");
        assert_eq!(choose(&mut Scripted::new(&["0", "3", "1"]), "x", "PHP?", &options, None).unwrap(), "8.2");
        assert!(choose(&mut Scripted::new(&[]), "x", "PHP?", &[], None).is_err());
        assert!(choose(&mut Scripted::new(&[]), "x", "PHP?", &options, Some("7.4")).is_err());
    }

    #[test]
    fn hidden_characters_cannot_redraw_the_screen() {
        let mut asker = Scripted::new(&["1"]);
        let options = vec!["a\u{1b}[2Jb\nfake".to_string()];
        choose(&mut asker, "x", "Pick\u{1b}[1A", &options, None).unwrap();
        assert!(!asker.shown[0].contains('\u{1b}'), "{}", asker.shown[0]);
        assert!(asker.shown[0].contains("a\\u{1b}[2Jb\\nfake"), "{}", asker.shown[0]);
    }

    #[test]
    fn prompts_need_the_terminal_permission() {
        let lua = crate::runtime::sandbox::new_lua().unwrap();
        install(&lua, false, "x").unwrap();
        for call in [r#"prompt.ask("q")"#, r#"prompt.confirm("q")"#, r#"prompt.choose("q", {"a"})"#] {
            let err = lua.load(call).exec().unwrap_err().to_string();
            assert!(err.contains(r#"needs "terminal": true"#), "{call}: {err}");
        }
    }
}
