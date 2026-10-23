# tb self mcp

Serves your commands as [MCP](https://modelcontextprotocol.io) tools, so Claude Code, Claude Desktop, Cursor and
other AI apps can call them directly instead of through a shell.

```
tb self mcp
```

No arguments. It talks MCP on stdin and stdout, so you don't run it yourself: your AI app starts it.

## Set it up

Claude Code:

```bash
claude mcp add toolbox -- tb self mcp
```

Apps with a JSON config (Claude Desktop, Cursor and others):

```json
{
  "mcpServers": {
    "toolbox": { "command": "tb", "args": ["self", "mcp"] }
  }
}
```

If the app can't find `tb`, use the full path from `which tb`.

## What the app sees

Every working command is one tool, with the same name and description. Its args become the tool's input:

| `command.json` | Tool input |
|----------------|------------|
| `"type": "string"`, `"integer"`, `"number"`, `"boolean"` | The same JSON type |
| `"required": true` | Listed as required |
| `"description"`, `"default"` | Passed along |

Broken commands are left out ([`tb self check`](check.md) shows why). The `tb self` built-ins are never tools.

When you or an agent add, remove or change a command, the app is told within a few seconds and fetches the new list.
A command an agent just wrote can be used right away.

## How a call runs

Each call runs `tb <command> --<arg>=<value>` as its own process, exactly like on the command line:

- The result is the command's JSON output.
- A failed run (a Lua `error`, a missing key, a bad argument) comes back as a tool error with the message, so the
  model can read it and fix its call.
- Lines the script writes with `print` or `log` come back in a second text block.
- `stdin.read()` returns an empty string: the script can't read the app's messages.
- Calls run side by side, so a slow command doesn't hold up the others.
- `false` for a boolean leaves the flag out. A flag that defaults to `true` can't be turned off from a tool call.

## API keys

Nothing changes. A command still needs your approval for each key ([`tb self vault allow`](vault.md)), and the
server has no terminal, so nothing reached through it can add, allow or read a key. When a key is missing or not
allowed, the tool error says what to ask you to run.

## See also

- [AI agents](../ai-agents.md): the `CLAUDE.md` snippet for agents that use the shell
- [Security](../security.md): what commands can touch
