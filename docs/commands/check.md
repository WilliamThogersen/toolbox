# tb self check

Validates every command and lists everything that is wrong.

```
tb self check
```

No arguments.

## What it does

For each folder in `~/.toolbox/commands/` it checks:

1. `command.json` exists and parses. Unknown fields are errors, so typos are caught.
2. The manifest rules: the name matches the folder, the description isn't empty, `version` is semver, arg types and
   defaults fit together, vault names are valid, `http` has no empty hosts.
3. `run.lua` exists and compiles. It is never run.

## Output

```json
{
  "ok": false,
  "commands": ["good"],
  "problems": [
    { "command": "typo", "problem": "invalid command.json: unknown field `descripton`, expected one of `name`, `version`, `description`, `args`, `permissions` at line 1 column 27" },
    { "command": "syntax", "problem": "syntax error: ...run.lua:1: <name> or '...' expected near 'end'" }
  ]
}
```

- `commands`: the commands with no problems.
- Exit code `0` when `ok` is `true`, `1` when there is any problem.

A broken command never breaks the others: `tb` still lists and runs every working one.

## See also

- [Writing commands](../writing-commands.md)
- [`tb self describe`](describe.md): the full manifests as JSON
