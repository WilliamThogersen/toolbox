//! End-to-end tests for `tb self install|update|uninstall` against local git repos.

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};
use tempfile::TempDir;

/// Keeps the developer's own git config (signing, hooks, templates) out of the tests.
const GIT_ISOLATION: &[(&str, &str)] = &[
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_AUTHOR_NAME", "test"),
    ("GIT_AUTHOR_EMAIL", "test@example.com"),
    ("GIT_COMMITTER_NAME", "test"),
    ("GIT_COMMITTER_EMAIL", "test@example.com"),
];

struct Toolbox {
    home: TempDir,
}

impl Toolbox {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
        }
    }

    fn commands_dir(&self) -> PathBuf {
        self.home.path().join("commands")
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_toolbox"));
        cmd.args(args)
            .envs(GIT_ISOLATION.iter().copied())
            .env("TOOLBOX_HOME", self.home.path())
            .env("TOOLBOX_INSECURE_TEST_VAULT", self.home.path().join("test-vault.json"))
            .stdin(Stdio::null());
        // Detach from any controlling terminal, like an AI agent's shell.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        cmd.output().unwrap()
    }

    fn json(&self, args: &[&str]) -> Value {
        let out = self.run(args);
        assert!(out.status.success(), "tb {args:?} failed: {}", stderr(&out));
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn error(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(!out.status.success(), "tb {args:?} should have failed");
        let err: Value = serde_json::from_str(stderr(&out).trim()).unwrap();
        err["error"].as_str().unwrap().to_string()
    }
}

/// A git repo that plays the part of a GitHub or GitLab repo.
struct Repo {
    dir: TempDir,
}

impl Repo {
    fn new() -> Self {
        let repo = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        repo.git(&["init", "--quiet", "--initial-branch", "main"]);
        repo
    }

    fn url(&self) -> String {
        format!("file://{}", self.dir.path().display())
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(self.dir.path())
            .args(args)
            .envs(GIT_ISOLATION.iter().copied())
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Writes `<folder>/command.json` and `<folder>/run.lua`. An empty folder means the repo root.
    fn write_command(&self, folder: &str, manifest: Value, script: &str) {
        let dir = self.dir.path().join(folder);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("command.json"), manifest.to_string()).unwrap();
        fs::write(dir.join("run.lua"), script).unwrap();
    }

    fn write_file(&self, path: &str, text: &str) {
        fs::write(self.dir.path().join(path), text).unwrap();
    }

    fn commit(&self, message: &str) -> String {
        self.git(&["add", "--all"]);
        self.git(&["commit", "--quiet", "--message", message]);
        self.git(&["rev-parse", "HEAD"])
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn manifest(name: &str, version: Option<&str>, permissions: Value) -> Value {
    let mut m = json!({ "name": name, "description": "Says something", "permissions": permissions });
    if let Some(version) = version {
        m["version"] = json!(version);
    }
    m
}

fn says(text: &str) -> String {
    format!("return function() return {text:?} end")
}

fn names(installed: &Value) -> Vec<&str> {
    installed.as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect()
}

#[test]
fn installs_every_folder_in_a_repo_and_runs_them() {
    let repo = Repo::new();
    repo.write_command("hello", manifest("hello", Some("1.0.0"), json!({})), &says("hi"));
    repo.write_command("stars", manifest("stars", None, json!({ "http": ["api.github.com"] })), &says("42"));
    repo.write_file("README.md", "# my tools");
    let commit = repo.commit("first");

    let tb = Toolbox::new();
    let installed = tb.json(&["self", "install", &repo.url(), "--yes"]);
    assert_eq!(names(&installed), vec!["hello", "stars"]);
    assert_eq!(installed[0]["version"], "1.0.0");
    assert_eq!(installed[1]["permissions"]["http"], json!(["api.github.com"]));
    assert_eq!(installed[0]["source"], json!({ "url": repo.url(), "commit": commit }));

    assert_eq!(tb.json(&["hello"]), json!("hi"));
    assert_eq!(tb.json(&["stars"]), json!("42"));
    assert_eq!(tb.json(&["self", "check"])["ok"], true);
    let files: Vec<String> = fs::read_dir(tb.commands_dir().join("hello"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(files.len(), 3, "only command.json, run.lua and .source.json: {files:?}");
    assert!(!tb.home.path().read_dir().unwrap().any(|e| {
        e.unwrap().file_name().to_string_lossy().starts_with(".staging")
    }));
}

#[test]
fn a_repo_with_command_json_at_the_root_is_one_command() {
    let repo = Repo::new();
    repo.write_command("", manifest("solo", Some("0.1.0"), json!({})), &says("alone"));
    repo.commit("first");

    let tb = Toolbox::new();
    assert_eq!(names(&tb.json(&["self", "install", &repo.url(), "--yes"])), vec!["solo"]);
    assert_eq!(tb.json(&["solo"]), json!("alone"));
}

#[test]
fn without_yes_or_a_terminal_it_shows_permissions_and_changes_nothing() {
    let repo = Repo::new();
    repo.write_command("pr", manifest("pr", Some("2.0.0"), json!({ "vault": ["github"], "http": ["api.github.com"] })), &says("x"));
    repo.commit("first");

    let tb = Toolbox::new();
    let err = tb.error(&["self", "install", &repo.url()]);
    assert!(err.contains("pr 2.0.0"), "{err}");
    assert!(err.contains("http: api.github.com; vault: github"), "{err}");
    assert!(err.contains("! vault uses your github key(s)"), "{err}");
    assert!(err.contains("--yes"), "{err}");
    assert!(!tb.commands_dir().join("pr").exists());
}

#[test]
fn broken_repos_and_taken_names_install_nothing() {
    let tb = Toolbox::new();

    let broken = Repo::new();
    broken.write_command("good", manifest("good", None, json!({})), &says("ok"));
    broken.write_command("bad", manifest("bad", Some("one"), json!({})), "return function( end");
    broken.commit("first");
    let err = tb.error(&["self", "install", &broken.url(), "--yes"]);
    assert!(err.contains("bad:") && err.contains("semver"), "{err}");
    assert!(!tb.commands_dir().join("good").exists());

    assert!(tb.error(&["self", "install", &Repo::new().url(), "--yes"]).contains("could not fetch"));

    tb.json(&["self", "new", "mine"]);
    let clash = Repo::new();
    clash.write_command("mine", manifest("mine", None, json!({})), &says("theirs"));
    clash.commit("first");
    let err = tb.error(&["self", "install", &clash.url(), "--yes"]);
    assert!(err.contains("a local command already has this name"), "{err}");
    assert_eq!(tb.json(&["mine"]), json!({ "message": "hello world" }));
}

#[test]
fn update_takes_a_higher_version_only() {
    let repo = Repo::new();
    repo.write_command("greet", manifest("greet", Some("1.0.0"), json!({})), &says("v1"));
    repo.commit("v1");
    let tb = Toolbox::new();
    tb.json(&["self", "install", &repo.url(), "--yes"]);

    repo.write_command("greet", manifest("greet", Some("1.0.0"), json!({})), &says("work in progress"));
    repo.commit("wip");
    let report = tb.json(&["self", "update"]);
    assert_eq!(report["up_to_date"], json!(["greet"]));
    assert_eq!(tb.json(&["greet"]), json!("v1"));

    repo.write_command("greet", manifest("greet", Some("1.1.0"), json!({})), &says("v1.1"));
    repo.commit("release 1.1.0");
    let err = tb.error(&["self", "update", "greet"]);
    assert!(err.contains("greet 1.0.0 -> 1.1.0 from file://"), "{err}");
    assert!(err.contains("permissions: no permissions"), "{err}");
    assert_eq!(tb.json(&["greet"]), json!("v1"), "every update asks first");
    let report = tb.json(&["self", "update", "greet", "--yes"]);
    assert_eq!(report["updated"], json!([{ "name": "greet", "from": "1.0.0", "to": "1.1.0" }]));
    assert_eq!(tb.json(&["greet"]), json!("v1.1"));
}

#[test]
fn update_without_versions_follows_commits() {
    let repo = Repo::new();
    repo.write_command("plain", manifest("plain", None, json!({})), &says("one"));
    repo.commit("one");
    let tb = Toolbox::new();
    tb.json(&["self", "install", &repo.url(), "--yes"]);
    assert_eq!(tb.json(&["self", "update"])["up_to_date"], json!(["plain"]));

    repo.write_command("plain", manifest("plain", None, json!({})), &says("two"));
    repo.commit("two");
    assert_eq!(tb.json(&["self", "update", "--yes"])["updated"][0]["name"], "plain");
    assert_eq!(tb.json(&["plain"]), json!("two"));
}

#[test]
fn update_shows_changed_permissions_with_warnings() {
    let repo = Repo::new();
    repo.write_command("tool", manifest("tool", Some("1.0.0"), json!({ "http": ["api.example.com"] })), &says("safe"));
    repo.commit("v1");
    let tb = Toolbox::new();
    tb.json(&["self", "install", &repo.url(), "--yes"]);

    let wider = json!({ "http": ["api.example.com"], "exec": ["sh"] });
    repo.write_command("tool", manifest("tool", Some("1.1.0"), wider), &says("shell"));
    repo.commit("v1.1");
    let err = tb.error(&["self", "update"]);
    assert!(err.contains("before: http: api.example.com"), "{err}");
    assert!(err.contains("after:  http: api.example.com; exec: sh"), "{err}");
    assert!(err.contains("! exec runs sh with any arguments"), "{err}");
    assert_eq!(tb.json(&["tool"]), json!("safe"));

    assert_eq!(tb.json(&["self", "update", "--yes"])["updated"][0]["to"], "1.1.0");
    assert_eq!(tb.json(&["tool"]), json!("shell"));
}

#[test]
fn a_pinned_ref_stays_put_until_reinstalled() {
    let repo = Repo::new();
    repo.write_command("pin", manifest("pin", Some("1.0.0"), json!({})), &says("tag"));
    repo.commit("v1");
    repo.git(&["tag", "v1.0.0"]);
    repo.write_command("pin", manifest("pin", Some("2.0.0"), json!({})), &says("main"));
    repo.commit("v2");

    let tb = Toolbox::new();
    tb.json(&["self", "install", &repo.url(), "--ref", "v1.0.0", "--yes"]);
    assert_eq!(tb.json(&["pin"]), json!("tag"));
    assert_eq!(tb.json(&["self", "update"])["up_to_date"], json!(["pin"]));

    let installed = tb.json(&["self", "install", &repo.url(), "--yes"]);
    assert_eq!(installed[0]["version"], "2.0.0");
    assert_eq!(tb.json(&["pin"]), json!("main"));
}

#[test]
fn update_reports_commands_that_left_the_repo() {
    let repo = Repo::new();
    repo.write_command("gone", manifest("gone", None, json!({})), &says("x"));
    repo.write_command("kept", manifest("kept", None, json!({})), &says("y"));
    repo.commit("first");
    let tb = Toolbox::new();
    tb.json(&["self", "install", &repo.url(), "--yes"]);

    fs::remove_dir_all(repo.dir.path().join("gone")).unwrap();
    repo.commit("drop gone");
    let out = tb.run(&["self", "update", "--yes"]);
    assert!(!out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["problems"][0]["command"], "gone");
    assert!(report["problems"][0]["problem"].as_str().unwrap().contains("no longer in"));
    assert_eq!(report["updated"][0]["name"], "kept");
    assert!(tb.commands_dir().join("gone").exists(), "a vanished command is kept, not deleted");
}

#[test]
fn uninstall_removes_installed_commands_and_leaves_local_ones() {
    let repo = Repo::new();
    repo.write_command("temp", manifest("temp", None, json!({})), &says("x"));
    repo.commit("first");
    let tb = Toolbox::new();
    tb.json(&["self", "install", &repo.url(), "--yes"]);
    tb.json(&["self", "new", "mine"]);

    assert_eq!(tb.json(&["self", "uninstall", "temp"]), json!({ "name": "temp", "uninstalled": true }));
    assert!(!tb.commands_dir().join("temp").exists());

    assert!(tb.error(&["self", "uninstall", "mine"]).contains("made locally"));
    assert!(tb.error(&["self", "uninstall", "../mine"]).contains("not a valid command name"));
    assert!(tb.commands_dir().join("mine").exists());
    assert!(tb.error(&["self", "update", "mine"]).contains("not an installed command"));
}

#[test]
fn install_help_lives_under_self_only() {
    let tb = Toolbox::new();
    let top = String::from_utf8_lossy(&tb.run(&[]).stdout).into_owned();
    assert!(!top.contains("install"), "{top}");
    let help = String::from_utf8_lossy(&tb.run(&["self", "--help"]).stdout).into_owned();
    for builtin in ["install", "update", "uninstall"] {
        assert!(help.contains(builtin), "missing {builtin}:\n{help}");
    }
}
