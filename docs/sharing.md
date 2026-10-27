# Sharing commands

Any git repo can hold toolbox commands: GitHub, GitLab, a self-hosted server, public or private. A repo can hold one
command or a whole marketplace of them. Others install with [`tb self install`](commands/install.md).

## Host your own

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
     notes/             a command with subcommands and shared code
       command.json
       add.lua
       list.lua
       lib/store.lua
   ```

   A repo with `command.json` and its Lua files at the root is a single command instead. See
   [subcommands and shared code](writing-commands.md#subcommands-and-shared-code) for the `notes` layout.
2. Give each command a `"version": "1.0.0"` in `command.json`.
3. Commit, then try it: `tb self install ./tb-tools --list` checks every command in your local repo, and
   `tb self install ./tb-tools` installs them.
4. Push, and share the clone URL. Others run `tb self install <url>`, or save it with
   `tb self market add <name> <url>`.

Rules for the folders:

- The folder name must equal the `name` in its `command.json`.
- Top-level folders without a `command.json` (like `docs/`) and hidden folders (like `.github/`) are ignored.
- `command.json` and the Lua files must be regular files. Symlinks are refused, so a repo can't make toolbox read
  files outside it.
- Only `command.json`, the scripts (`run.lua`, or one `<subcommand>.lua` each) and `lib/*.lua` are copied. Scripts
  can't read other files, so put everything a command needs in those.

## Releasing a new version

Bump `version` in the command's `command.json`, commit and push. That's the release.

[`tb self update`](commands/update.md) only takes a version higher than the installed one, so commits without a bump
never reach anyone. That lets you push work in progress safely. A command without a `version` updates on every new
commit instead.

Every update asks the user first and shows whether the permissions changed. Asking for new permissions in an update
is fine, but users will see it.

To offer a stable channel, keep a `stable` branch or tag releases (`v1.2.0`): users can install or save a marketplace
with `--ref stable`.

## Run a marketplace

A marketplace is a repo with many command folders. Nothing else is needed: no index file, no registry.

- Give each command a clear `description`. [`tb self search`](commands/search.md) matches names and descriptions.
- Keep names short and specific. Users type them as `<market>/<name>`.
- A broken command only hides itself: users can still install every other command in the repo.
- Ask for the fewest permissions that work. The install prompt marks `exec`, `http: ["*"]`, `env` and `vault` as
  risky, and careful users will say no.

Users add it once:

```console
$ tb self market add acme https://github.com/acme/tb-market.git
$ tb self search weather
$ tb self install acme/weather
```

## What gets installed

Each installed command is a normal folder in `~/.toolbox/commands/` plus a `.source.json`:

```json
{
  "url": "https://github.com/acme/tb-market.git",
  "ref": "stable",
  "commit": "a1b2c3d4e5f6...",
  "market": "acme",
  "fingerprint": "9f86d081884c7d65..."
}
```

`ref` is only there when the user installed with `--ref`, `market` only when they installed through a marketplace.
`fingerprint` covers `command.json` and every Lua file as installed, so
[`tb self describe --origin`](commands/describe.md#origins) can tell when someone edited them. `tb self update` reads this file to know where to look.
[`tb self uninstall`](commands/uninstall.md) only removes folders that have it.
