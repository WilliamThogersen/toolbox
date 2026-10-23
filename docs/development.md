# Development

## Build and test

```bash
cargo build
cargo test                  # unit + end-to-end tests
cargo clippy --all-targets  # keep at 0 warnings
```

The Rust version is pinned in `rust-toolchain.toml`: rustup installs it on the first build.

Tests use `TOOLBOX_HOME` (a temp folder) and `TOOLBOX_INSECURE_TEST_VAULT` (a plain JSON vault file). Never put real
keys in that file. To try the dev binary the same way:

```bash
TOOLBOX_HOME=/tmp/tbhome TOOLBOX_INSECURE_TEST_VAULT=/tmp/tbhome/vault.json target/debug/toolbox self new hello
```

The end-to-end tests in `tests/cli.rs` (vault, sandbox) and `tests/install.rs` (install, update, marketplaces) run
the real binary, detached from any terminal like an agent's shell. The install tests use local git repos, so no
network is needed.

## Docs

Every `tb self` command has a page in `docs/commands/`, linked from `docs/README.md`. A test fails when a command,
subcommand or flag is missing from its page. `docs/writing-commands.md` is built into the binary and printed by
`tb self guide`.

## Demo GIF

The README's `assets/demo.gif` is recorded with [VHS](https://github.com/charmbracelet/vhs) from
`assets/demo/demo.tape`. Record it again after changing anything it shows:

```bash
brew install vhs
cargo build --release && vhs assets/demo/demo.tape
```

The tape uses a throwaway `TOOLBOX_HOME` in `/tmp/toolbox-demo`, the plain-text test vault, a fake key and the
`peek` command in `assets/demo/peek/`. The last scene calls httpbin.org, so it needs the network.

## Releasing

1. Bump `version` in `Cargo.toml`, run `cargo build` (updates `Cargo.lock`) and commit.
2. Write the release notes in a file, then make an annotated tag and push:
   `git tag -a v0.2.0 -F notes.md && git push origin main v0.2.0`

The tag's message becomes the GitHub release notes. Git drops lines that start with `#`, so use `**bold**` lines
instead of Markdown headings.

The [release workflow](../.github/workflows/release.yml) runs the tests, builds a signed universal macOS binary,
publishes the GitHub release and updates the formula in
[WilliamThogersen/homebrew-tap](https://github.com/WilliamThogersen/homebrew-tap). It stops if the tag doesn't
match the version in `Cargo.toml`.

After each release, and every Monday, [brew-check](../.github/workflows/brew-check.yml) installs toolbox from the tap
on a clean Mac and fails if it isn't the latest release. Run it by hand with `gh workflow run brew-check.yml`.

## Project layout

| Path | What |
|------|------|
| `src/manifest.rs` | `command.json` schema and validation |
| `src/registry.rs` | Finds and loads command folders |
| `src/cli.rs` | Top level: your commands, built from manifests |
| `src/builtin.rs` | `tb self`: every built-in command |
| `src/install/` | Install from git repos and marketplaces, version-aware updates, `.source.json` |
| `src/runtime/` | Lua sandbox, `http`, `json`, `exec`, `env`, `vault` globals |
| `src/vault/` | Keychain storage, placeholder injection, redaction, `vault` subcommands |
| `src/update.rs` | Once-a-day new-version notice on the terminal |
| `docs/` | These docs. `docs/writing-commands.md` is printed by `tb self guide` |
| `assets/demo/` | The VHS tape and the command behind the README's demo GIF |
