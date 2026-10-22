# toolbox

A toolbox CLI that an AI can keep extending. Every command is a folder with a
`command.json` (name, args, permissions) and a `run.lua` (the logic). Drop a
folder in `~/.toolbox/commands/` and it is a new subcommand. No rebuild.

`tb` and `toolbox` are the same program: `tb` is a symlink for typing less.

## Install

```bash
scripts/install.sh        # builds, installs ~/.cargo/bin/toolbox + tb, signs it on macOS
```

## Quick start

```bash
tb new hello --description "Says hello"   # creates ~/.toolbox/commands/hello/
tb hello --name you                        # {"message": "hello you"}
tb describe                                # every command as JSON
tb guide                                   # how to write commands (Lua API)
tb check                                   # validates everything, exit 1 on problems
```

Output is always JSON on stdout. Errors are `{"error": "..."}` on stderr with exit code 1.

## Let your AI use it

Add this to your `CLAUDE.md`:

```markdown
## toolbox (tb)
`tb` is my toolbox CLI. Run `tb describe` to see the available commands.
To add a command, read `tb guide`, then `tb new <name>`, edit the files, and run `tb check`.
API keys live in the toolbox vault: use `vault("name")` in headers, never ask me for a key.
If a key is missing, ask me to run `tb vault add <name> --host <host>`.
```

## Vault: keys the AI can use but never see

1. In your own terminal: `tb vault add github --host api.github.com`. Paste the key at the hidden prompt.
2. In a command: list `"vault": ["github"]` under `permissions` and send
   `Authorization = "Bearer " .. vault("github")` as a header.
3. The first time toolbox reads the vault, macOS asks if `toolbox` may use the keychain item `toolbox`. Click **Always Allow**.

`tb vault list` shows names and hosts. `tb vault rm <name>` deletes a secret (asks for confirmation).

### What it protects against

- Scripts never get the value. `vault("github")` returns the placeholder `{{vault:github}}`.
- toolbox swaps in the real key only in **header values**, only for hosts you allowed, only over https (http for localhost only).
- Requests that carry a key ignore redirects and `HTTP_PROXY`-style env vars.
- Any key that shows up in a response (raw, base64 or URL-encoded) is replaced with `[REDACTED:<name>]`.
- Adding and removing keys needs a human at a real terminal (`/dev/tty`). An AI's shell has none.
- The vault is one macOS Keychain item. Other programs, like the `security` CLI, trigger a macOS permission prompt.
- `scripts/install.sh` signs toolbox with the hardened runtime, so `DYLD_INSERT_LIBRARIES` and debuggers can't get inside it.

### What it does not protect against

- **A rebuilt toolbox.** If an AI edits the Rust source and rebuilds it, the new binary can do anything. macOS asks again
  before a changed binary reads the keychain: only click Allow right after you ran `scripts/install.sh` yourself.
- **A host that echoes the key in a changed form** (part of it, hashed, re-encoded). Redaction only catches exact copies.
- **Other platforms.** On Linux and Windows the keychain storage works, but the hardened-runtime signing is macOS only.

## Layout

| Path | What |
|------|------|
| `src/manifest.rs` | `command.json` schema and validation |
| `src/registry.rs` | Finds and loads command folders |
| `src/cli.rs` | Builds subcommands from manifests, dispatches |
| `src/runtime/` | Lua sandbox, `http`, `json`, `exec`, `env`, `vault` globals |
| `src/vault/` | Keychain storage, placeholder injection, redaction, `vault` subcommands |
| `src/guide.md` | Text printed by `tb guide` |

## Development

```bash
cargo test                  # unit + end-to-end tests
cargo clippy --all-targets
```

Tests use `TOOLBOX_HOME` (a temp folder) and `TOOLBOX_INSECURE_TEST_VAULT` (a plain JSON vault file). Never put real keys in that file.
