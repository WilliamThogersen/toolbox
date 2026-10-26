# Using toolbox from an AI agent

toolbox is made for AI agents to extend: a new command is two files, and the output is always JSON.

## Tell your agent about it

For Claude Code, run once:

```bash
tb self init
```

It writes [the instructions](agent-instructions.md) to `~/.claude/TOOLBOX.md` and adds `@TOOLBOX.md` to
`~/.claude/CLAUDE.md`, so every session uses your commands first and writes new ones when one is missing. Run it
again after upgrading toolbox to refresh the text. See [`tb self init`](commands/init.md).

Other agents: copy [the instructions](agent-instructions.md) into their instructions file.

## Or give it the commands as tools

Apps that speak [MCP](https://modelcontextprotocol.io) can call your commands as tools instead of through a shell:

```bash
claude mcp add toolbox -- tb self mcp
```

New commands show up as tools within a few seconds. See [`tb self mcp`](commands/mcp.md). Writing new commands
still happens in the shell, so run `tb self init` too.

## Output rules

| What | Where |
|------|-------|
| The result | stdout, as JSON. Nothing else is ever written to stdout. |
| Errors | stderr as `{"error": "..."}`, exit code `1`. Plain text when stderr is a terminal. |
| `print` and `log` from scripts | stderr |
| The new-version notice | stderr, only when stderr is a terminal. Agents never see it. |

The one exception is [`tb self guide`](commands/guide.md), which prints Markdown to read.

A closed stdout pipe (`tb ... | head`) is not an error.

## What an agent can and can't do

| Can | Can't |
|-----|-------|
| Write commands, run them, check them | Read a key's value |
| Use keys in commands the human allowed, for hosts the human allowed | Add, change, allow or delete keys (needs your Touch ID or password) |
| Search marketplaces | Install or update without `--yes` (it gets the permission list instead) |
| Uninstall installed commands | Delete commands the human made |

## Where to start

1. `tb self init`: tell Claude Code about toolbox
2. `tb self describe`: what exists, with args and permissions
3. `tb self guide`: how to write a command
4. `tb self search <words>`: what others already wrote
