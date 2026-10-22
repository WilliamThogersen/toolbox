# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`toolbox` is a Rust CLI (installed as `toolbox` with a `tb` symlink) whose commands are defined at runtime, not compiled in. Each command is a folder `$TOOLBOX_HOME/commands/<name>/` (default `~/.toolbox`) holding `command.json` (name, args, permissions) and `run.lua` (Lua 5.4, sandboxed). It also has a vault: API keys that commands can use in HTTP headers without the script (or the AI writing it) ever seeing the value.

## Commands

```bash
cargo build
cargo test                              # unit tests + end-to-end tests
cargo test --test cli                   # end-to-end tests only (tests/cli.rs)
cargo test vault::inject                # one module's unit tests
cargo test --test cli secret_requests   # one end-to-end test by name filter
cargo clippy --all-targets              # keep at 0 warnings
```

Run the dev binary against a throwaway home and a plain-text test vault (never put real keys in it):

```bash
TOOLBOX_HOME=/tmp/tbhome TOOLBOX_INSECURE_TEST_VAULT=/tmp/tbhome/vault.json target/debug/toolbox self new hello
```

Without `TOOLBOX_INSECURE_TEST_VAULT`, vault commands hit the real macOS Keychain item (service `toolbox`, account `vault`).

## Architecture

**Startup flow** (`main.rs` -> `cli.rs`): load every command folder (`registry.rs`), build the clap app dynamically with one subcommand per valid manifest, then dispatch. Broken commands never break startup: they are collected as `Problem`s and surfaced by `tb self check` and `tb self describe`.

**Top level vs `self`**: plain `tb` lists only the user's commands (custom help template in `cli.rs`, clap's help subcommand and `-h`/`-V` hidden). All built-ins (`new`, `check`, `describe`, `guide`, `install`, `update`, `uninstall`, `vault`) live under the hidden `self` namespace in `builtin.rs`. New built-in features go under `tb self`, never the top level. Reserved top-level names are in `manifest::RESERVED_NAMES`.

**Output contract**: stdout carries only the JSON result. Lua `print`/`log` go to stderr. Errors are `{"error": ...}` on stderr with exit 1 (plain text when stderr is a TTY). A closed stdout pipe is not an error (`cli::ignore_closed_pipe`). After every run, `update::notify` may print a new-version notice to stderr: only when stderr is a TTY and `TOOLBOX_NO_UPDATE_CHECK` is unset, asking the GitHub releases API at most once a day (cached in `$TOOLBOX_HOME/update-check.json`), so agents never see it.

**Runtime** (`src/runtime/`): every run gets a fresh Lua state. `sandbox.rs` removes `io`, `os`, `load`, `dofile`, `loadfile`, `require`, `string.dump`. `api.rs` installs `json`, `log`/`print`, `env`, `vault`, `exec`, and `http.rs` installs `http`. Every global is gated by a field in `manifest::Permissions`. `run.lua` must return a function. Its return value is converted to JSON. Use `runtime::ser_options()` whenever converting JSON into Lua so JSON `null` becomes `nil`.

**Installing from git** (`src/install/`): `tb self install <url>` fetches one commit with the user's own `git` (`git.rs`: `init` + `fetch --depth 1`, so `--ref` takes a branch, tag or SHA). `repo.rs` finds commands at the repo root or one per top-level folder, rejects symlinks and checks manifests plus Lua syntax: any problem installs nothing. Only `command.json` and `run.lua` are copied, plus `.source.json` (url, ref, commit), through a staging folder in `$TOOLBOX_HOME` so the final move is a rename. `update.rs` compares the manifest's semver `version` when both sides have one, else the commit, and asks before every update (new code needs a yes, even with the same permissions). `confirm::warnings` labels risky permissions (`exec`, `http *`, `env`, `vault`) in both prompts. Asking goes through the `Confirm` trait: `Prompt` needs a TTY and otherwise fails with the permission summary, `Yes` is `--yes`. `uninstall` only removes folders that have `.source.json`.

**Adding a Lua capability** touches three places: the `Permissions` struct (manifests use `deny_unknown_fields`, so new fields must be declared), the binding in `src/runtime/`, and `src/guide.md`. `guide.md` is compiled in and printed by `tb self guide`: it is the API reference AI agents read before writing commands, so keep it in sync.

## Vault invariants (security-critical)

The design goal: an agent with full shell access that writes `run.lua` and `command.json` must not be able to read a stored key.

- Secret values never enter the Lua state. `vault("name")` only returns the placeholder `{{vault:name}}`. Substitution happens only in `runtime/http.rs` via `vault::inject::inject_headers`, in header values only. Placeholders in the URL, body or header names are errors.
- `inject::authorize` requires all of: the secret is listed in the manifest's `permissions.vault`, it exists, the URL is https (plain http only for loopback), and the host is in the secret's human-set `hosts`.
- Requests carrying a secret use the `secret_safe` agent: no redirects, no env proxy. Responses and error strings go through `inject::Redactor` before Lua sees them.
- The whole vault is a single Keychain item, so host bindings can't be edited without the Keychain's permission prompt. Storage goes through the `VaultStore` trait: `KeychainStore`, `FileStore` (tests only), `MemoryStore` (unit tests).
- `vault add` and `vault rm` read from `/dev/tty` through the `Terminal` trait, so an agent's shell (no controlling TTY) cannot add, change or delete keys. The end-to-end tests detach with `setsid` to reproduce this.
- Never add a command or API that returns secret values. `SecretValue`'s `Debug` is redacted, and `expose()` belongs only in the injection path.
- The end-to-end tests in `tests/cli.rs` (redaction, host binding, proxy bypass, exfiltration attempts, TTY requirement) are the security spec. They run the real binary against local TCP echo/proxy servers on loopback. Keep them passing when touching `src/vault/` or `src/runtime/http.rs`.

Known limits (documented in README): a rebuilt binary can read the vault after the user approves the Keychain prompt, and redaction only catches exact (raw, base64, URL-encoded) copies of a key.

## Repo

Pushes go to the `main` branch of `github.com/WilliamThogersen/toolbox` through a repo-local credential helper (`git config --local -l`). Don't change the global `gh` account to push.

Releases: pushing a `v*` tag runs `.github/workflows/release.yml`. It requires the tag to equal `v` + the `Cargo.toml` version, runs the tests, builds one universal macOS binary signed with the hardened runtime (`codesign --sign - --options runtime`), publishes the GitHub release, then renders `.github/homebrew/toolbox.rb` into `Formula/toolbox.rb` of `WilliamThogersen/homebrew-tap`. The push to the tap uses the deploy key in the `HOMEBREW_TAP_DEPLOY_KEY` secret. Users install with `brew install WilliamThogersen/tap/toolbox`. `.github/workflows/brew-check.yml` runs after each release, weekly and on demand: it installs from the tap on a clean runner and fails unless that is the latest release, signed with the hardened runtime, passing `brew test` and `brew audit --strict`.
