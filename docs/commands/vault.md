# tb self vault

API keys that commands can use but never see. The keys live in the macOS Keychain.

```
tb self vault add <name> --host <host>... [--query-param <param>...]
tb self vault list
tb self vault allow <secret> <command>
tb self vault revoke <secret> <command>
tb self vault rm <name>
```

Every change needs a person at a real terminal. An AI agent's shell has none, so it can't add, change, allow or
delete anything.

A key is used only when three things line up:

1. It goes to a host you set with `--host`.
2. It goes in a header, or in a query parameter you named with `--query-param`.
3. The command was allowed with `tb self vault allow`, and hasn't changed since.

## tb self vault add

Adds a key. Run it again for an existing key to change where it may go: leave the value empty to keep the key you
have. Commands you allowed stay allowed.

| Argument | Meaning |
|----------|---------|
| `<name>` | The name scripts use: `vault("<name>")`. `a-z`, `0-9`, `-`, `_`. |
| `--host <host>` | A host the key may be sent to, like `api.github.com`. Repeat it or use commas for several. Add a port to allow only that port: `api.example.com:8443`. No `https://`, path or wildcard. |
| `--query-param <param>` | A query parameter the key may also be sent in, for APIs that want `?key=...`. Repeat it or use commas for several. Without it, the key only goes in headers. |

It asks for the value at a hidden prompt. The value must be at least 8 characters on one line.

```console
$ tb self vault add github --host api.github.com
Value for github (input is hidden):
{ "name": "github", "hosts": ["api.github.com"], "query_params": [], "commands": [] }
```

The first time toolbox reads the vault, macOS asks if `toolbox` may use the keychain item `toolbox`. Click
**Always Allow**.

### Keys for a server on this computer

Name the exact address and port your server listens on: `--host 127.0.0.1:8080`, or `--host [::1]:8080` for IPv6.
Commands then call that address, like `http://127.0.0.1:8080/`.

- **A port is required.** Without one, any program on your machine, an AI agent included, could listen on a port of
  its choosing and receive the key.
- **`localhost` is refused.** It means both `127.0.0.1` and `::1`, and another program can listen on the one your
  server doesn't use. `0.0.0.0` and `*.localhost` are refused for the same reason.
- **Whatever listens there gets the key.** Have your server listen on exactly that address. If it listens on all
  addresses (`0.0.0.0`), macOS lets another program of yours listen on `127.0.0.1` with the same port and take the
  connections. While your server is stopped, any program can.

Keys added before these rules with a local host and no port stop working until you add them again with one.

### Basic auth

For APIs that log in with a user and password (or user and token), store both as one value, `user:password`, and
use `vault("<name>", "base64")` in the command. See
[Writing commands](../writing-commands.md#vault-api-keys-you-can-use-but-never-see).

### Older versions of toolbox

The vault's stored format changed so that toolbox 0.3.0 and older, which know nothing about approvals, can't use your
keys without them. Once you add, allow, revoke or remove anything with this version, an older one sees an empty vault.

## tb self vault list

Each key's rules and the commands that use it. Never values.

```json
[{
  "name": "github",
  "hosts": ["api.github.com"],
  "query_params": [],
  "commands": [
    { "name": "gh-stars", "access": "allowed" },
    { "name": "gh-issues", "access": "changed" },
    { "name": "gh-new", "access": "not_allowed" }
  ]
}]
```

| `access` | Meaning |
|----------|---------|
| `allowed` | You allowed it and it hasn't changed. |
| `changed` | You allowed it, but its `command.json` or `run.lua` changed since. Allow it again after reading the changes. |
| `not_allowed` | It lists the key in `permissions.vault`, but you never allowed it. |
| `missing` | You allowed it, but it's gone or broken. |

## tb self vault allow

Lets a command use a key. It prints the command's permissions, its whole `run.lua`, and where the key may go, then
asks. Read the script: once allowed, the command can do anything the key allows on those hosts.

| Argument | Meaning |
|----------|---------|
| `<secret>` | The key. |
| `<command>` | The command. It must list the key in `permissions.vault`. |

```json
{ "secret": "github", "command": "gh-stars", "allowed": true }
```

`allowed` is `false` when you answer no.

The approval covers exactly the files you saw. Any later change, by you, by an AI agent or by
[`tb self update`](update.md), takes the access away until you allow the command again.

## tb self vault revoke

Stops a command from using a key, after asking for confirmation on the terminal.

| Argument | Meaning |
|----------|---------|
| `<secret>` | The key. |
| `<command>` | The command to take it away from. |

```json
{ "secret": "github", "command": "gh-stars", "revoked": true }
```

## tb self vault rm

Deletes a key after asking for confirmation on the terminal.

| Argument | Meaning |
|----------|---------|
| `<name>` | The key to delete. |

```json
{ "name": "github", "deleted": true }
```

`deleted` is `false` when you answer no.

## Using a key in a command

1. Add `"vault": ["github"]` under `permissions` in `command.json`.
2. Send it in a header: `Authorization = "Bearer " .. vault("github")`.
3. Run `tb self vault allow github <command>` in your terminal.

The script only ever sees the placeholder `{{vault:github}}`. toolbox swaps in the real key while sending, and only
to the hosts you set. See [Writing commands](../writing-commands.md#vault-api-keys-you-can-use-but-never-see).

## See also

- [Security](../security.md#the-vault): what the vault protects against, and what it doesn't
