<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/toolbox-wordmark-dark.svg">
    <img alt="toolbox" src="assets/toolbox-wordmark-light.svg" width="360">
  </picture>
</h1>

<p align="center">
  <strong>A CLI your AI can keep extending.</strong><br>
  Commands are small Lua scripts. API keys stay in the keychain, out of the AI's reach.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-f97316"></a>
  <img alt="Rust 2024" src="https://img.shields.io/badge/rust-2024-1c1917?logo=rust">
  <img alt="Lua 5.5" src="https://img.shields.io/badge/lua-5.5-1c1917?logo=lua">
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#writing-a-command">Writing a command</a> ·
  <a href="#share-commands-through-git">Share commands</a> ·
  <a href="#let-your-ai-use-it">Let your AI use it</a> ·
  <a href="#the-vault">The vault</a>
</p>

Every command is a folder with a `command.json` (name, args, permissions) and a `run.lua` (the logic).
Drop a folder in `~/.toolbox/commands/` and it is a new subcommand. No rebuild.

- **New command, new folder.** An AI can add a tool in seconds and use it right away.
- **JSON out, always.** Results go to stdout as JSON. Errors are `{"error": "..."}` on stderr with exit code 1.
- **Nothing it didn't ask for.** Each command lists the hosts, programs, env vars and keys it may touch. Everything else fails.
- **Keys the AI can use but never see.** Scripts get a placeholder. toolbox swaps in the real key only on the way out.

`tb` and `toolbox` are the same program: `tb` is a symlink for typing less.

## Install

```bash
brew install WilliamThogersen/tap/toolbox
```

This installs `toolbox` and `tb` (macOS, Apple Silicon and Intel). Update with `brew upgrade toolbox`.

When a new version is out, `tb` says so on your terminal. It asks GitHub at most once a day, and only when a
person is at the terminal: agents and pipes never see the notice. Set `TOOLBOX_NO_UPDATE_CHECK=1` to turn it off.

## Quick start

```console
$ tb self new hello --description "Says hello"
$ tb hello --name you
{
  "message": "hello you"
}
$ tb
Usage: tb <command> [args]

Commands:
  hello  Says hello

Manage commands and API keys: tb self
```

Plain `tb` lists only your own commands. Everything that manages the toolbox itself lives under `tb self`:

| Command | What it does |
|---------|--------------|
| `tb self new <name>` | Create a command from a template |
| `tb self check` | Validate every command, exit 1 on problems |
| `tb self describe` | Every command, its args and permissions, as JSON |
| `tb self guide` | How to write commands (manifest format and Lua API) |
| `tb self install <source>` | Install commands from a git repo or a saved marketplace |
| `tb self search [<text>]` | Search the commands in every saved marketplace |
| `tb self market` | Save, list and remove marketplaces |
| `tb self update [<name>]` | Update installed commands to their newest version |
| `tb self uninstall <name>` | Remove an installed command |
| `tb self vault` | Add, list and remove API keys |

## Writing a command

`~/.toolbox/commands/stars/command.json`:

```json
{
  "name": "stars",
  "version": "1.0.0",
  "description": "Star count for a GitHub repo",
  "args": {
    "repo": { "type": "string", "required": true, "description": "owner/repo" }
  },
  "permissions": {
    "http": ["api.github.com"]
  }
}
```

`~/.toolbox/commands/stars/run.lua`:

```lua
return function(args)
  local res = http.get("https://api.github.com/repos/" .. args.repo, {
    headers = { ["User-Agent"] = "toolbox" },
  })
  if res.status ~= 200 then error("GitHub returned " .. res.status) end
  return { repo = res.json.full_name, stars = res.json.stargazers_count }
end
```

```console
$ tb stars --repo rust-lang/rust
{
  "repo": "rust-lang/rust",
  "stars": 120656
}
```

Scripts run in a sandboxed Lua 5.5 with no `io`, `os` or `require`. Instead they get these globals, each one gated by
`permissions`:

| Global | What it does | Permission |
|--------|--------------|------------|
| `http` | `get`, `post`, `put`, `patch`, `delete`, `request` | `http`: allowed hosts |
| `exec` | Run a program with a list of args, no shell | `exec`: allowed programs |
| `env` | `env.get("NAME")` | `env`: allowed variables |
| `vault` | `vault("name")` gives a placeholder for a key | `vault`: allowed keys |
| `json` | `json.encode`, `json.decode`, `json.null` | none |
| `log` | Write to stderr (`print` does too) | none |

`tb self guide` prints the full reference (also in [`src/guide.md`](src/guide.md)).

## Share commands through git

Any git repo can hold toolbox commands: GitHub, GitLab, a self-hosted server, public or private. A repo can hold
one command or a whole marketplace of them.

### Install

```console
$ tb self install https://gitlab.com/alice/tb-tools.git
From https://gitlab.com/alice/tb-tools.git at a1b2c3d:
  pr-status 0.3.0  http: api.github.com; vault: github
    ! vault uses your github key(s) on the hosts you allowed for them
  stars 1.0.0      http: api.github.com
Install 2 commands? [y/N] y
```

toolbox fetches the repo with your own `git`, so private repos work through your SSH keys or git credentials.
Without names it installs every working command and lists the broken ones it skipped. Name commands to pick them:
a name that is missing, broken or already used by another command stops the install, and nothing is installed.

| Command | What it does |
|---------|--------------|
| `tb self install <url> stars pr-status` | Install only these commands from the repo |
| `tb self install <url> --list` | Show the repo's commands and permissions as JSON, install nothing |
| `tb self install <url> --ref v1.2.0` | Install a branch, tag or commit instead of the default branch |
| `tb self install <url> --yes` | Skip the question (scripts and agents have no terminal to answer on) |
| `tb self update` | Update every installed command (asks first). `tb self update stars` updates one |
| `tb self uninstall stars` | Remove an installed command. Commands you made yourself are never touched |

### Marketplaces

Save a repo once under a short name, then search it and install by name:

```console
$ tb self market add acme https://github.com/acme/tb-market.git
$ tb self search github
{
  "results": [
    { "market": "acme", "name": "stars", "version": "1.0.0", "description": "Star count for a GitHub repo", ... }
  ],
  "problems": []
}
$ tb self install acme/stars
```

- `tb self install acme stars pr-status` picks several commands from `acme`.
- `tb self search` without words lists everything. It fetches each marketplace fresh, so results are never stale.
- `tb self market list` shows saved marketplaces. `tb self market rm acme` forgets one: its installed commands stay
  and keep updating from its URL.
- `tb self market add acme <url> --ref stable` follows a branch or tag instead of the default branch.

Marketplaces are saved in `~/.toolbox/markets.json`.

### Host your own

1. Create a git repo with one folder per command:

   ```
   tb-tools/
     README.md          anything else in the repo is ignored
     stars/
       command.json
       run.lua
     pr-status/
       command.json
       run.lua
   ```

   A repo with `command.json` and `run.lua` at the root is a single command.
2. Give each command a `"version": "1.0.0"` in `command.json`.
3. Commit, then try it: `tb self install ./tb-tools` works on a local repo too and checks every command.
   Then push.
4. Share the clone URL. Others run `tb self install <url>`, or save it as a marketplace with
   `tb self market add <name> <url>`.

A marketplace is just a repo with many command folders. `tb self search` matches names and descriptions, so give each
command a clear `description`.

To release a new version, bump `version` and push. `tb self update` only takes a version higher than the installed
one, so commits without a bump never reach anyone. A command without a `version` updates on every new commit.

Only `command.json` and `run.lua` are copied, plus a `.source.json` that records the repo and commit.

### Before you install

An installed command runs someone else's code with every permission it asks for. The prompt marks the risky
ones with `!`. Read the list first:

- `exec` runs programs on your machine. `exec: ["sh"]` or `["bash"]` means a full shell.
- `vault` uses your keys. They still only go to the hosts you bound them to, but the command decides what it does there.
- `http: ["*"]` may call any host.

Every update asks first: it lists the new version, the repo to review it in, and its permissions (before and
after when they changed). Without a terminal it stops unless you pass `--yes`. A hacked repo can't slip new code in
on a routine update. To stay on code you reviewed, install a tag or commit with `--ref`: updates then stay on it
until you install another `--ref`.

## Let your AI use it

Add this to your `CLAUDE.md` (or your agent's instructions file):

```markdown
## toolbox (tb)
`tb` is my toolbox CLI. Run `tb` to list my commands and `tb self describe` for their args as JSON.
To add a command, read `tb self guide`, then `tb self new <name>`, edit the files, and run `tb self check`.
API keys live in the toolbox vault: use `vault("name")` in headers, never ask me for a key.
If a key is missing, ask me to run `tb self vault add <name> --host <host>`.
Before writing a new command, check `tb self search <words>` for one in my marketplaces.
Before `tb self install <source> --yes`, show me the permissions it lists and wait for my OK.
```

## The vault

API keys your AI can use but never see.

1. In your own terminal, run `tb self vault add github --host api.github.com` and paste the key at the hidden prompt.
2. In the command, add `"vault": ["github"]` under `permissions`.
3. Send the key as a header: `Authorization = "Bearer " .. vault("github")`.

The first time toolbox reads the vault, macOS asks if `toolbox` may use the keychain item `toolbox`. Click **Always Allow**.

`tb self vault list` shows names and hosts, never values. `tb self vault rm <name>` deletes a key (asks for confirmation).

### What it protects against

- **Scripts never get the value.** `vault("github")` returns the placeholder `{{vault:github}}`.
- **Keys only go where you said.** toolbox swaps in the real key only in header values, only for hosts you allowed,
  only over https (http for localhost only).
- **No detours.** Requests that carry a key ignore redirects and `HTTP_PROXY`-style env vars.
- **No echoes.** A key that shows up in a response (raw, base64 or URL-encoded) is replaced with `[REDACTED:<name>]`.
- **A human adds and removes keys.** That needs a real terminal (`/dev/tty`). An AI's shell has none.
- **Other programs get asked.** The vault is one macOS Keychain item, so tools like the `security` CLI trigger a permission prompt.
- **No injection.** Release binaries are signed with the hardened runtime, so `DYLD_INSERT_LIBRARIES` and debuggers can't get inside them.

### What it does not protect against

- **A rebuilt toolbox.** If an AI edits the Rust source and rebuilds it, the new binary can do anything. macOS asks again
  before a changed binary reads the keychain: only click Allow right after you installed or upgraded toolbox yourself.
- **A host that echoes the key in a changed form** (part of it, hashed, re-encoded). Redaction only catches exact copies.
- **Other platforms.** Releases are macOS only. Built from source on Linux or Windows the keychain storage works,
  but there is no hardened-runtime signing.

## Development

```bash
cargo test                  # unit + end-to-end tests
cargo clippy --all-targets
```

The Rust version is pinned in `rust-toolchain.toml`: rustup installs it on the first build.

Tests use `TOOLBOX_HOME` (a temp folder) and `TOOLBOX_INSECURE_TEST_VAULT` (a plain JSON vault file). Never put real keys in that file.

### Releasing

1. Bump `version` in `Cargo.toml`, run `cargo build` (updates `Cargo.lock`) and commit.
2. Tag and push: `git tag v0.2.0 && git push origin main v0.2.0`

The [release workflow](.github/workflows/release.yml) runs the tests, builds a signed universal macOS binary,
publishes the GitHub release and updates the formula in
[WilliamThogersen/homebrew-tap](https://github.com/WilliamThogersen/homebrew-tap).
It stops if the tag doesn't match the version in `Cargo.toml`.

After each release, and every Monday, [brew-check](.github/workflows/brew-check.yml) installs toolbox from the tap
on a clean Mac and fails if it isn't the latest release. Run it by hand with `gh workflow run brew-check.yml`.

<details>
<summary>Project layout</summary>

| Path | What |
|------|------|
| `src/manifest.rs` | `command.json` schema and validation |
| `src/registry.rs` | Finds and loads command folders |
| `src/cli.rs` | Top level: your commands, built from manifests |
| `src/builtin.rs` | `tb self`: new, check, describe, guide, install, update, uninstall, vault |
| `src/install/` | Fetch commands from git repos and marketplaces, `.source.json`, version-aware updates |
| `src/runtime/` | Lua sandbox, `http`, `json`, `exec`, `env`, `vault` globals |
| `src/vault/` | Keychain storage, placeholder injection, redaction, `vault` subcommands |
| `src/guide.md` | Text printed by `tb self guide` |
| `src/update.rs` | Once-a-day new-version notice on the terminal |

</details>

## License

[MIT](LICENSE)
