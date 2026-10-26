# tb self init

Tells Claude Code about toolbox, so it reaches for your commands first and writes new ones when one is missing.

```
tb self init [--remove]
```

| Argument | Meaning |
|----------|---------|
| `--remove` | Take it out again: removes the `@TOOLBOX.md` line from `CLAUDE.md` and deletes `TOOLBOX.md`. |

## What it does

1. Writes [the instructions](../agent-instructions.md) to `~/.claude/TOOLBOX.md`. The text is built into the binary,
   so it matches the toolbox version you have installed.
2. Adds an `@TOOLBOX.md` line to the end of `~/.claude/CLAUDE.md`, which makes Claude Code read the file in every
   session. The rest of `CLAUDE.md` stays as it is. Both files are created if they don't exist.

Run it again after upgrading toolbox: it refreshes `TOOLBOX.md` and never adds a second import line. It only replaces
or deletes a `TOOLBOX.md` that it wrote itself (the file starts with a `Written by tb self init` comment), and stops
with an error if you have your own file by that name.

If `CLAUDE.md` still has the `## toolbox (tb)` section pasted from older docs, it says so on stderr and in `note`.
Delete that section: `TOOLBOX.md` replaces it.

Set `CLAUDE_CONFIG_DIR` to use another folder than `~/.claude`, the same variable Claude Code reads.

## Output

```json
{
  "claude_md": "/Users/you/.claude/CLAUDE.md",
  "instructions": "/Users/you/.claude/TOOLBOX.md",
  "imported": true,
  "updated": true
}
```

`imported` is `false` when the import line was already there, `updated` is `false` when `TOOLBOX.md` already had
this version's text.

With `--remove`:

```json
{
  "claude_md": "/Users/you/.claude/CLAUDE.md",
  "instructions": "/Users/you/.claude/TOOLBOX.md",
  "import_removed": true,
  "deleted": true
}
```

## See also

- [AI agents](../ai-agents.md): output rules, what agents can and can't do
- [`tb self mcp`](mcp.md): give Claude your commands as tools as well
