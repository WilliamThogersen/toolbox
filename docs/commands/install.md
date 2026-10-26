# tb self install

Installs commands from a git repo or a saved marketplace.

```
tb self install <source> [<command>...] [--ref <ref>] [--list] [--yes]
```

| Argument | Meaning |
|----------|---------|
| `<source>` | Where the commands come from. See [Sources](#sources). |
| `<command>...` | Only install these commands. Without names: every working command in the repo. |
| `--ref <ref>` | A branch, tag or commit to install. Default: the repo's default branch. |
| `--list` | Show the repo's commands as JSON and install nothing. |
| `--yes`, `-y` | Don't ask first. Needed when there is no terminal (scripts, AI agents). |

## Sources

| You type | It means |
|----------|----------|
| `https://github.com/alice/tb-tools.git` | A git URL. GitHub, GitLab, self-hosted, any host |
| `git@gitlab.com:alice/tb-tools.git` | An SSH URL, using your SSH keys |
| `./tb-tools` or `/path/to/tb-tools` | A local repo (its last commit) |
| `acme` | The saved marketplace `acme`. See [`tb self market`](market.md) |
| `acme/stars` | The command `stars` from the saved marketplace `acme` |

A name like `acme` always means a saved marketplace. To use a local folder with that name, write `./acme`.

## What it does

1. Fetches one commit of the repo with your own `git`, so private repos work through your SSH keys or git credentials.
2. Checks every command in it: the manifest, the Lua syntax, and that `command.json` and `run.lua` are regular files
   (symlinks are refused).
3. Picks the commands: the ones you named, or every working one. Broken commands nobody asked for are skipped and
   listed.
4. Shows each command's permissions, marks the risky ones with `!`, and asks.
5. Copies `command.json` and `run.lua` into `~/.toolbox/commands/<name>/`, plus a `.source.json` that records the
   repo, ref and commit for [`tb self update`](update.md), the marketplace when you named one, and a fingerprint of
   the two files so [`tb self describe --origin`](describe.md#origins) can tell when they were edited. Nothing else in
   the repo is copied.

The prompt:

```console
$ tb self install https://gitlab.com/alice/tb-tools.git
From https://gitlab.com/alice/tb-tools.git at a1b2c3d:
  pr-status 0.3.0  http: api.github.com; vault: github
    ! vault uses your github key(s) on the hosts you allowed for them
  stars 1.0.0      http: api.github.com
Skipped, broken:
  old-tool: syntax error: old-tool/run.lua:1: <name> or '...' expected near 'end'
Install 2 commands? [y/N]
```

Installing again from the same repo replaces the installed copies. Use that to move to another `--ref`.

## Output

```json
{
  "installed": [
    {
      "name": "stars",
      "version": "1.0.0",
      "permissions": { "http": ["api.github.com"], "vault": [], "exec": [], "env": [] },
      "dir": "/Users/you/.toolbox/commands/stars",
      "source": { "url": "https://gitlab.com/alice/tb-tools.git", "commit": "a1b2c3d4e5f6...", "fingerprint": "9f86d081..." }
    }
  ],
  "skipped": [
    { "command": "old-tool", "problem": "syntax error: old-tool/run.lua:1: ..." }
  ]
}
```

With `--list`:

```json
{
  "url": "https://gitlab.com/alice/tb-tools.git",
  "commit": "a1b2c3d4e5f6...",
  "commands": [
    {
      "name": "stars",
      "version": "1.0.0",
      "description": "Star count for a GitHub repo",
      "permissions": { "http": ["api.github.com"], "vault": [], "exec": [], "env": [] },
      "installed": false
    }
  ],
  "broken": []
}
```

## Examples

```console
$ tb self install https://github.com/alice/tb-tools.git            # every working command
$ tb self install https://github.com/alice/tb-tools.git stars      # just one
$ tb self install https://github.com/alice/tb-tools.git --ref v1.2.0
$ tb self install acme/stars                                        # from a saved marketplace
$ tb self install acme stars pr-status                              # several from one marketplace
$ tb self install ./tb-tools --list                                 # what's in a local repo
```

## When it stops

Nothing is installed when:

- The repo can't be fetched, or has no commands at all.
- A command you named isn't in the repo, or is broken.
- A name is already used by a command you made yourself, or by one installed from another repo.
- You answer no, or there is no terminal and you didn't pass `--yes`. The error then shows the full permission list,
  so an agent can show it to you first.

## See also

- [Security](../security.md#installing-other-peoples-commands): what an installed command can do
- [Sharing commands](../sharing.md): host your own repo or marketplace
- [`tb self update`](update.md), [`tb self uninstall`](uninstall.md)
