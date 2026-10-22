# Using toolbox from an AI agent

toolbox is made for AI agents to extend: a new command is two files, and the output is always JSON.

## Tell your agent about it

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
| Use keys in headers, for hosts the human allowed | Add, change or delete keys (needs a real terminal) |
| Search marketplaces | Install or update without `--yes` (it gets the permission list instead) |
| Uninstall installed commands | Delete commands the human made |

## Where to start

1. `tb self describe`: what exists, with args and permissions
2. `tb self guide`: how to write a command
3. `tb self search <words>`: what others already wrote
