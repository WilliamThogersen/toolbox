use std::io::{self, BufRead, IsTerminal, Write};

use anyhow::{Result, bail};

use crate::command::manifest::{Manifest, Permissions};

pub trait Confirm {
    fn confirm(&self, summary: &str, question: &str) -> Result<bool>;
}

pub struct Prompt;

impl Confirm for Prompt {
    fn confirm(&self, summary: &str, question: &str) -> Result<bool> {
        if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
            bail!(
                "{summary}\nNothing changed: there is no terminal to ask on. Check the permissions above, then run again with --yes"
            );
        }
        let mut stderr = io::stderr().lock();
        write!(stderr, "{summary}\n{question} [y/N] ")?;
        stderr.flush()?;
        let mut answer = String::new();
        io::stdin().lock().read_line(&mut answer)?;
        Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
    }
}

pub struct Yes;

impl Confirm for Yes {
    fn confirm(&self, _summary: &str, _question: &str) -> Result<bool> {
        Ok(true)
    }
}

pub fn label(manifest: &Manifest) -> String {
    match &manifest.version {
        Some(version) => format!("{} {version}", manifest.name),
        None => manifest.name.clone(),
    }
}

pub fn permissions(perms: &Permissions) -> String {
    let parts: Vec<String> = [
        ("http", &perms.http),
        ("vault", &perms.vault),
        ("exec", &perms.exec),
        ("env", &perms.env),
        ("read", &perms.read),
        ("write", &perms.write),
    ]
    .into_iter()
    .filter(|(_, values)| !values.is_empty())
    .map(|(kind, values)| format!("{kind}: {}", values.join(", ")))
    .chain(flags(perms))
    .collect();
    if parts.is_empty() {
        "no permissions".to_string()
    } else {
        parts.join("; ")
    }
}

fn flags(perms: &Permissions) -> impl Iterator<Item = String> {
    [("terminal", perms.terminal), ("background", perms.background)]
        .into_iter()
        .filter(|(_, on)| *on)
        .map(|(flag, _)| flag.to_string())
}

pub fn warnings(perms: &Permissions) -> Vec<String> {
    let mut lines = Vec::new();
    if !perms.exec.is_empty() {
        lines.push(format!(
            "exec runs {} with any arguments. Treat it as full access to your machine",
            perms.exec.join(", ")
        ));
    }
    if perms.http.iter().any(|host| host == "*") {
        lines.push("http * can send data to any host".to_string());
    }
    if !perms.env.is_empty() {
        lines.push(format!("env reads {}, which may hold secrets", perms.env.join(", ")));
    }
    if !perms.vault.is_empty() {
        lines.push(format!(
            "vault uses your {} key(s) on the hosts you allowed for them",
            perms.vault.join(", ")
        ));
    }
    if !perms.read.is_empty() {
        lines.push(format!("read sees every file in {}", perms.read.join(", ")));
    }
    if !perms.write.is_empty() {
        lines.push(format!(
            "write can change and delete files in {}",
            perms.write.join(", ")
        ));
    }
    if perms.terminal {
        lines.push("terminal asks you questions and can hand your terminal to the programs it runs".to_string());
    }
    if perms.background {
        lines.push("background starts programs that keep running after the command ends".to_string());
    }
    lines
}

pub fn warning_lines(perms: &Permissions) -> String {
    warnings(perms).iter().map(|w| format!("\n    ! {w}")).collect::<Vec<_>>().concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_risky_permissions_get_warnings() {
        let calm = Permissions {
            http: vec!["api.github.com".into()],
            ..Permissions::default()
        };
        assert!(warnings(&calm).is_empty());
        let risky = Permissions {
            http: vec!["*".into()],
            vault: vec!["github".into()],
            exec: vec!["git".into()],
            env: vec!["AWS_SECRET_ACCESS_KEY".into()],
            read: vec!["~/notes".into()],
            write: vec![".".into()],
            terminal: true,
            background: true,
        };
        let text = warnings(&risky).join("\n");
        assert!(text.contains("terminal asks you questions"), "{text}");
        assert!(text.contains("background starts programs that keep running"), "{text}");
        assert!(text.contains("exec runs git") && text.contains("full access"), "{text}");
        assert!(text.contains("any host"), "{text}");
        assert!(text.contains("env reads AWS_SECRET_ACCESS_KEY"), "{text}");
        assert!(text.contains("your github key"), "{text}");
        assert!(text.contains("read sees every file in ~/notes"), "{text}");
        assert!(text.contains("write can change and delete files in ."), "{text}");
    }

    #[test]
    fn permissions_read_as_one_line() {
        assert_eq!(permissions(&Permissions::default()), "no permissions");
        let perms = Permissions {
            http: vec!["api.github.com".into(), "github.com".into()],
            vault: vec!["github".into()],
            ..Permissions::default()
        };
        assert_eq!(permissions(&perms), "http: api.github.com, github.com; vault: github");
        let talks = Permissions { exec: vec!["ssh".into()], terminal: true, background: true, ..Permissions::default() };
        assert_eq!(permissions(&talks), "exec: ssh; terminal; background");
    }
}
