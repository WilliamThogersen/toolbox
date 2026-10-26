# toolbox docs

## Commands

Plain `tb` lists only your own commands. Everything that manages toolbox lives under `tb self`:

| Command | What it does |
|---------|--------------|
| [`tb self new <name>`](commands/new.md) | Create a command from a template |
| [`tb self check`](commands/check.md) | Validate every command, exit 1 on problems |
| [`tb self describe`](commands/describe.md) | Every command, its args and permissions, as JSON |
| [`tb self guide`](commands/guide.md) | Print the reference for writing commands |
| [`tb self install <source>`](commands/install.md) | Install commands from a git repo or a saved marketplace |
| [`tb self search [<text>]`](commands/search.md) | Search the commands in every saved marketplace |
| [`tb self update [<name>]`](commands/update.md) | Update installed commands to their newest version |
| [`tb self uninstall <name>`](commands/uninstall.md) | Remove an installed command |
| [`tb self market`](commands/market.md) | Save, list and remove marketplaces |
| [`tb self vault`](commands/vault.md) | API keys: agents request them, you paste them and choose which commands may use them |
| [`tb self mcp`](commands/mcp.md) | Serve your commands as MCP tools for Claude Code and other AI apps |
| [`tb self init`](commands/init.md) | Tell Claude Code to use toolbox: writes `~/.claude/TOOLBOX.md` and imports it |

Your own commands run as `tb <name> --<arg> <value>`. Add `--help` to see their args.

## Guides

- [Writing commands](writing-commands.md): `command.json`, the Lua API, the vault. Also printed by `tb self guide`.
- [Sharing commands](sharing.md): host your own repo or marketplace, release versions.
- [Security](security.md): what commands can touch, the risks of installing, what the vault protects.
- [AI agents](ai-agents.md): `tb self init`, output rules, what agents can and can't do.
- [Development](development.md): build, test, release, project layout.
