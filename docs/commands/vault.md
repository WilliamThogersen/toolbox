# tb self vault

API keys that commands can use but never see. The keys live in the macOS Keychain.

The vault is macOS only for now. On Linux the system keyring (GNOME Keyring, KWallet) hands stored keys to any program
you run, an AI agent included, so there the vault commands and `vault()` refuse with an error that says so. Commands
that don't use keys work everywhere. See [Security](../security.md#what-it-does-not-protect-against).

```
tb self vault request <name> --host <host>... --why <text> [--query-param <param>...] [--note <text>]
tb self vault setup [<command>]
tb self vault add <name> --host <host>... [--query-param <param>...]
tb self vault list
tb self vault allow <secret> <command>
tb self vault revoke <secret> <command>
tb self vault rm <name>
tb self vault log [--key <key>] [--command <command>] [--limit <n>]
```

Every change asks twice: at the terminal, then in a macOS dialog for Touch ID or your login password that says
what is about to change. An AI agent's shell has no terminal, and an agent that fakes one still can't answer the
dialog. Over SSH there is no dialog, so changes need the Mac itself.

A key is used only when three things line up:

1. It goes to a host you set with `--host`.
2. It goes in a header, or in a query parameter you named with `--query-param`.
3. The command was allowed with `tb self vault setup` or `tb self vault allow`, and hasn't changed since.

## The quick way

Let your AI agent prepare everything. You only paste the key:

1. The agent writes the command and runs `tb self vault request <name> --host <host> --why <text>`. That needs no
   terminal and doesn't touch the vault.
2. You run `tb self vault setup`. It shows each requested key and why it's needed, asks you to paste it, shows the
   command's script and asks yes or no. One Touch ID saves it all.

```console
$ tb self vault setup

Key pagespeed was requested
  why: Run Lighthouse audits on your sites through Google's PageSpeed API
  note: Get it at https://console.cloud.google.com/apis/credentials
  used by lighthouse
Hosts it may go to (Enter keeps www.googleapis.com, - skips this key):
Query parameters it may go in (Enter keeps key, - for headers only):
Paste the key for pagespeed (input is hidden, empty skips it):
lighthouse wants to use your key pagespeed
  ...
Allow lighthouse to use pagespeed? [y/N, v = read the whole script] y
{ "added": ["pagespeed"], "allowed": [{ "key": "pagespeed", "command": "lighthouse" }], "declined": [], "skipped": [] }
```

After an agent edits a command, run `tb self vault setup` again to review the changes.

## tb self vault request

Asks you for a key. Meant for AI agents: it needs no terminal, and it only writes a request to
`~/.toolbox/vault-requests.json`. The key is stored when you run [`tb self vault setup`](#tb-self-vault-setup).

| Argument | Meaning |
|----------|---------|
| `<name>` | The key's name, with the same rules as for [`add`](#tb-self-vault-add). |
| `--host <host>` | Where the key should go, up to 5. You see them at `setup` and can change them. Same rules as for `add`. |
| `--query-param <param>` | A query parameter the key should also go in, up to 5. Same rules as for `add`. |
| `--why <text>` | Required. What the key is needed for, shown to you at `setup`. One line of plain text, up to 200 characters. |
| `--note <text>` | Shown to you at `setup` too, like where to get the key. One line of plain text, up to 200 characters. |

```json
{
  "requested": "pagespeed",
  "hosts": ["www.googleapis.com"],
  "query_params": ["key"],
  "why": "Run Lighthouse audits on your sites through Google's PageSpeed API",
  "used_by": ["lighthouse"],
  "next": "Ask the user to run `tb self vault setup` in their own terminal. ..."
}
```

`used_by` lists the commands whose `permissions.vault` covers the key. A request for a key that is already in the
vault is refused: to change where an existing key may go, use [`add`](#tb-self-vault-add). A new request for the
same name replaces the old one. At most 20 requests wait at a time. `setup` checks the file again, and leaves out
entries that are broken, repeated or past the limit.

**Read the hosts before you press Enter.** Whoever made the request picked them, and wrote the why. The Touch ID
dialog names the hosts again.

## tb self vault setup

Everything waiting for you, in one go:

1. **Requested keys.** For each one: why it's needed, then where it may go (Enter keeps what the request says, or type other hosts), then
   the value at a hidden prompt. An empty value or `-` at the hosts prompt skips the key and keeps its request for
   next time.
2. **Commands waiting for a key.** Each command's review screen, the same one [`allow`](#tb-self-vault-allow) shows,
   then one yes or no per key. A command waits when it lists a key by name and was never allowed, when a key was
   just added for it, or when it changed since you allowed it.

Nothing is saved until the end, so `Ctrl-C` changes nothing. Then one Touch ID covers every key added and every
command allowed. The dialog names each change, starting with commands that get a key you already had. When you go
through everything, a command whose `run.lua` can't be read is skipped with a note on stderr.

| Argument | Meaning |
|----------|---------|
| `<command>` | Only this command. Also asks for keys it lists that nobody requested (with its host as the default, if it calls only one), and for keys a pattern like `github/*` covers. |

```json
{
  "added": ["pagespeed"],
  "allowed": [{ "key": "pagespeed", "command": "lighthouse" }],
  "declined": [],
  "skipped": []
}
```

With nothing waiting it changes nothing, needs no terminal and prints all four lists empty. When `setup` left out
entries of the requests file, it adds `"ignored_requests": <count>` and removes them from the file.

## tb self vault add

Adds a key. Run it again for an existing key to change where it may go: leave the value empty to keep the key you
have. Commands you allowed stay allowed.

| Argument | Meaning |
|----------|---------|
| `<name>` | The name scripts use: `vault("<name>")`. `a-z`, `0-9`, `-`, `_`, in up to 3 parts split by `/` for several accounts: `github/work`, `jira/acme/token`. |
| `--host <host>` | A host the key may be sent to, like `api.github.com`. Repeat it or use commas for several. Add a port to allow only that port: `api.example.com:8443`. No `https://`, path or wildcard. |
| `--query-param <param>` | A query parameter the key may also be sent in, for APIs that want `?key=...`. Repeat it or use commas for several. Without it, the key only goes in headers. |

It asks for the value at a hidden prompt. The value must be at least 8 characters on one line.

```console
$ tb self vault add github --host api.github.com
Value for github (input is hidden):
{ "name": "github", "hosts": ["api.github.com"], "query_params": [], "commands": [] }
```

### Several accounts

Put each account's key in a folder named after the service:

```console
$ tb self vault add github/work --host api.github.com
$ tb self vault add github/personal --host api.github.com
```

A command that lists `"vault": ["github/*"]` can pick one at run time, like `tb gh-stars --account work`. You still
allow each key on its own: allowing `github/work` doesn't give the command `github/personal`. See
[Writing commands](../writing-commands.md#several-accounts).

The first time toolbox reads the vault, macOS asks if `toolbox` may use the keychain item `toolbox`. Click
**Always Allow**. On Linux your keyring may ask for its password if it is locked.

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

The vault's stored format changed so older versions can't skip rules they don't know: 0.3.0 and older know nothing
about approvals, and 0.4.0 to 0.6.0 don't ask for Touch ID. Once you add, allow, revoke or remove anything with this
version, 0.3.0 sees an empty vault and 0.4.0 to 0.6.0 refuse to open it.

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

Lets a command use a key. It shows the command's permissions, where the key may go, and every line of its `run.lua`
that reaches outside the script, with line numbers: calls to `http`, `exec`, `fs`, `env`, `stdin` and `vault`, and
URLs. Answer `v` to read the whole script in a pager, then `y` or `n`. Once allowed, the command can do anything the
key allows on those hosts.

```
lighthouse wants to use your key pagespeed
  Google Lighthouse for a URL via the PageSpeed API
  permissions: http: www.googleapis.com; vault: pagespeed
    ! vault uses your pagespeed key(s) on the hosts you allowed for them
  pagespeed may be sent to www.googleapis.com (also as query parameter key)

Lines of its run.lua (171 in all) that reach outside the script:
    3  local API = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
  132    local ok, res = pcall(http.get, API, {
  137        key = vault("pagespeed"),

Once allowed, this exact version can do anything the key allows on those hosts.

Allow lighthouse to use pagespeed? [y/N, v = read the whole script]
```

| Argument | Meaning |
|----------|---------|
| `<secret>` | The key. |
| `<command>` | The command. It must list the key in `permissions.vault`, or a pattern covering it like `github/*`. |

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

## tb self vault log

What happened to your keys, newest first: requested, added, allowed, declined, revoked, removed, used and refused.
Never values.

| Flag | Meaning |
|------|---------|
| `--key <key>` | Only entries for this key. |
| `--command <command>` | Only entries for this command. |
| `--limit <n>` | How many entries to show. Default 50. |

```json
[
  {
    "time": "2026-10-23T09:12:03+02:00",
    "event": "used",
    "keys": ["pagespeed"],
    "command": "lighthouse",
    "request": { "method": "GET", "host": "www.googleapis.com", "path": "/pagespeedonline/v5/runPagespeed" },
    "outcome": { "status": 200 },
    "by": ["/opt/homebrew/Cellar/toolbox/0.6.0/bin/toolbox", "~/.local/share/claude/versions/2.1.308", "/bin/zsh"],
    "terminal": false
  },
  {
    "time": "2026-10-23T09:05:51+02:00",
    "event": "allowed",
    "key": "pagespeed",
    "command": "lighthouse",
    "by": ["/bin/zsh", "/usr/bin/login", "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"],
    "terminal": true
  }
]
```

| Field | Meaning |
|-------|---------|
| `event` | `requested`, `added`, `allowed`, `declined`, `revoked`, `removed`, `used` or `refused`. |
| `request` | Where a key went: method, host and path. Never the query string, which can hold the key. |
| `outcome` | `{ "status": 200 }`, or `{ "failed": "..." }` when no answer came back. |
| `reason` | Why a key was refused, for `refused`. |
| `by` | The programs that started `tb`, nearest first, by path (`~` is your home folder). Claude Code shows as `~/.local/share/claude/versions/<version>`, and `toolbox` first means the [MCP server](mcp.md) ran it. |
| `terminal` | Whether a person's terminal was attached. An agent's shell and MCP calls have none. |

The log is the file `~/.toolbox/vault-log.jsonl`, readable only by you. Past 5 MB it starts over and keeps the
previous one as `vault-log.1.jsonl`.

### The copy an agent can't change

An AI agent with your shell could edit or delete that file. Every entry also goes to the macOS system log, which it
can't change, and which records the path of the program that wrote each entry:

```bash
log show --last 7d --style compact --predicate 'process == "toolbox" AND eventMessage BEGINSWITH "vault "'
```

macOS keeps it for days to weeks, depending on disk space.

## Using a key in a command

1. Add `"vault": ["github"]` under `permissions` in `command.json`.
2. Send it in a header: `Authorization = "Bearer " .. vault("github")`.
3. If the key isn't stored yet: `tb self vault request github --host api.github.com`.
4. Run `tb self vault setup` in your terminal.

The script only ever sees the placeholder `{{vault:github}}`. toolbox swaps in the real key while sending, and only
to the hosts you set. See [Writing commands](../writing-commands.md#vault-api-keys-you-can-use-but-never-see).

## See also

- [Security](../security.md#the-vault): what the vault protects against, and what it doesn't
