# Development

## Build and test

```bash
cargo build
cargo test                  # unit + end-to-end tests
cargo clippy --all-targets  # keep at 0 warnings
cargo deny --target aarch64-apple-darwin check  # dependency advisories, licenses, sources (cargo install cargo-deny)
```

The lint levels are in `Cargo.toml`'s `[lints]` table and the thresholds in `clippy.toml`, so a plain
`cargo clippy` checks what CI checks. [Code rules](code-rules.md) explains them.

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

The [release workflow](../.github/workflows/release.yml) stops if the tag doesn't match the version in
`Cargo.toml`. Then it runs the tests and builds on each platform:

| Asset | Built on | What |
|-------|----------|------|
| `toolbox-macos.tar.gz` | `macos-latest` | One universal binary (Apple Silicon and Intel), signed with the hardened runtime |
| `toolbox-linux-x86_64.tar.gz` | `ubuntu-24.04` | Static musl binary, runs on any distribution whatever its glibc |
| `toolbox-linux-arm64.tar.gz` | `ubuntu-24.04-arm` | The same for arm64 |

Each Linux build runs on a native runner for its architecture, so the tests run there too, against the musl
target that ships. When all three pass, it publishes the GitHub release with the archives and `SHA256SUMS`, and
renders [`.github/homebrew/toolbox.rb`](../.github/homebrew/toolbox.rb) (one url and sha256 per platform) into the
formula in [WilliamThogersen/homebrew-tap](https://github.com/WilliamThogersen/homebrew-tap).

After each release, and every Monday, [brew-check](../.github/workflows/brew-check.yml) installs toolbox from the tap
on a clean Mac and on clean Linux runners (x86_64 and arm64), and fails if it isn't the latest release, or if
`brew test` or `brew audit --strict` fail. On macOS it also checks the hardened runtime, on Linux that the binary is
static and that the vault is off. Run it by hand with
`gh workflow run brew-check.yml`.

## CI

[ci](../.github/workflows/ci.yml) runs `cargo test` and `cargo clippy --all-targets -- -D warnings` on macOS and
Linux for every push to `main` and every pull request. [deny](../.github/workflows/deny.yml) checks the dependencies
against `deny.toml` (security advisories, licenses, sources) for each shipped target, on the same triggers and every
day, since new advisories appear without any change here.

To run the suite on Linux from a Mac, use a container with its own target folder (never share `target/` with the
host):

```bash
docker run --rm -v "$PWD":/src -w /src -e CARGO_TARGET_DIR=/tmp/target rust:1-bookworm \
  bash -c 'cargo test && rustup component add clippy && cargo clippy --all-targets -- -D warnings'
```

The image's rustup installs the pinned toolchain without clippy, hence the `rustup component add`.

## Project layout

| Path | What |
|------|------|
| `src/main.rs` | The only file in the `src/` root |
| `src/cli/` | Top level: your commands, built from manifests. Also arg lookups without panics, data paths, terminal-safe text, the new-version notice |
| `src/builtin/` | `tb self`: one file per built-in command (`app.rs` defines them all) |
| `src/command/` | `command.json` schema and validation (`manifest.rs`), finding and loading command folders (`registry.rs`) |
| `src/sys/` | Every C and macOS framework call, the only code with `unsafe` |
| `src/install/` | Install from git repos and marketplaces, version-aware updates, `.source.json` |
| `src/mcp/` | `tb self mcp`: commands as MCP tools over stdio |
| `src/runtime/` | Lua sandbox, `http`, `json`, `exec`, `env`, `vault` globals |
| `src/vault/` | Placeholder injection, redaction, `vault` subcommands. `platform/` holds the Keychain store (macOS) and the refusal elsewhere |
| `docs/` | These docs. `docs/writing-commands.md` is printed by `tb self guide`, `docs/agent-instructions.md` is written by `tb self init` |
| `assets/demo/` | The VHS tape and the command behind the README's demo GIF |
