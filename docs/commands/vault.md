# tb self vault

API keys that commands can use but never see. The keys live in the macOS Keychain.

```
tb self vault add <name> --host <host>...
tb self vault list
tb self vault rm <name>
```

Adding and removing keys needs a person at a real terminal. An AI agent's shell has none, so it can't add, change or
delete keys.

## tb self vault add

Adds a key, or replaces one with the same name.

| Argument | Meaning |
|----------|---------|
| `<name>` | The name scripts use: `vault("<name>")`. `a-z`, `0-9`, `-`, `_`. |
| `--host <host>` | A host the key may be sent to, like `api.github.com`. Repeat it or use commas for several. Just the hostname: no `https://`, port, path or wildcard. |

It asks for the value at a hidden prompt. The value must be at least 8 characters on one line.

```console
$ tb self vault add github --host api.github.com
Value for github (input is hidden):
{ "name": "github", "hosts": ["api.github.com"] }
```

The first time toolbox reads the vault, macOS asks if `toolbox` may use the keychain item `toolbox`. Click
**Always Allow**.

## tb self vault list

Names and hosts, never values.

```json
[{ "name": "github", "hosts": ["api.github.com"] }]
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

The script only ever sees the placeholder `{{vault:github}}`. toolbox swaps in the real key while sending, and only
to the hosts you set. See [Writing commands](../writing-commands.md#vault-api-keys-you-can-use-but-never-see).

## See also

- [Security](../security.md#the-vault): what the vault protects against, and what it doesn't
