# tb self describe

Prints every command with its args and permissions as JSON. This is how an AI agent finds out what it can run.

```
tb self describe
```

No arguments.

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

- `commands`: each manifest exactly as `command.json` defines it.
- `broken`: commands that failed to load. Lua syntax isn't checked here: use [`tb self check`](check.md) for that.
- `commands_dir`: where command folders live. Set `TOOLBOX_HOME` to move it.

## See also

- [`tb self check`](check.md)
- [Using toolbox from an AI agent](../ai-agents.md)
