# tb self describe

Prints every command with its args and permissions as JSON. This is how an AI agent finds out what it can run.

```
tb self describe [--origin]
```

| Argument | Meaning |
|----------|---------|
| `--origin` | Also print `origins`: where each command came from and whether it was edited since install. Made for apps and people; agents don't need it. |

## Output

```json
{
  "toolbox_version": "0.1.0",
  "commands_dir": "/Users/you/.toolbox/commands",
  "commands": [
    {
      "name": "stars",
      "version": "1.0.0",
      "description": "Star count for a GitHub repo",
      "args": {
        "repo": { "type": "string", "required": true, "description": "owner/repo" }
      },
      "permissions": { "http": ["api.github.com"], "vault": [], "exec": [], "env": [] }
    }
  ],
  "broken": [
    { "command": "typo", "problem": "invalid command.json: unknown field `descripton`, expected one of `name`, `version`, `description`, `args`, `permissions` at line 1 column 27" }
  ],
  "next": "Run `tb self guide` to learn how to add a command. Run `tb self vault list` to see which API keys exist."
}
```

- `commands`: each manifest exactly as `command.json` defines it. A command with
  [subcommands](../writing-commands.md#subcommands-and-shared-code) has a `subcommands` map instead of top-level
  `args`: run one as `tb <command> <subcommand> --<arg> <value>`.
- `broken`: commands that failed to load. Lua syntax isn't checked here: use [`tb self check`](check.md) for that.
- `commands_dir`: where command folders live. Set `TOOLBOX_HOME` to move it.

## Origins

With `--origin`, the output also has `origins`, one entry per command folder (broken ones included), keyed by name:

```json
"origins": {
  "stars": {
    "kind": "installed",
    "url": "https://github.com/acme/tb-market.git",
    "commit": "a1b2c3d4e5f6...",
    "market": "acme",
    "fingerprint": "9f86d081884c7d65...",
    "edited": false
  },
  "hello": {
    "kind": "created",
    "time": "2026-10-26T11:02:13+01:00",
    "by": ["~/.local/share/claude/versions/2.1.0", "/bin/zsh", "/Applications/Ghostty.app/Contents/MacOS/ghostty"],
    "terminal": false
  },
  "by-hand": { "kind": "unknown" }
}
```

| `kind` | Meaning |
|--------|---------|
| `installed` | Has a `.source.json` from [`tb self install`](install.md): `url`, `ref` (when installed with `--ref`), `commit`, and `market` when installed through a [marketplace](market.md). `edited` is `true` when `command.json` or a Lua file no longer match what was installed, and `null` for installs from toolbox 0.8.0 and older, which kept no fingerprint. |
| `created` | Made with [`tb self new`](new.md), which writes `.created.json`: when, the programs that ran `tb` (the same chain as the [key log](vault.md#tb-self-vault-log)), and whether a terminal was attached. An AI agent's shell usually has none. |
| `unknown` | Neither file: the folder was made by hand, or by a toolbox older than 0.9.0. |
| `unreadable` | A record exists but can't be used (`problem` says why): broken JSON, not a plain file, or over 64 KB. |

These files sit in the command folder, where any program of yours can write, an agent included. Read them as hints,
not proof: the vault's approvals are what decide whether a command may use a key.

## See also

- [`tb self check`](check.md)
- [Using toolbox from an AI agent](../ai-agents.md)
