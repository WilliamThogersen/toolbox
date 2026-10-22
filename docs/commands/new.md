# tb self new

Creates a working starter command that you then edit.

```
tb self new <name> [--description <text>]
```

| Argument | Meaning |
|----------|---------|
| `<name>` | The command name. 1 to 64 characters of `a-z`, `0-9`, `-`, `_`, starting with a letter or digit. `self` and `help` are reserved. |
| `--description <text>` | The line shown next to the command in `tb`. Default: `TODO: describe what this command does`. |

## What it does

Creates `~/.toolbox/commands/<name>/` with two files:

- `command.json`: the name, `"version": "0.1.0"`, the description, one optional `--name` string arg, and no permissions.
- `run.lua`: returns `{ message = "hello " .. name }`.

The command works right away, so you can run it before you change anything.

## Output

```json
{
  "dir": "/Users/you/.toolbox/commands/hello",
  "files": [
    "/Users/you/.toolbox/commands/hello/command.json",
    "/Users/you/.toolbox/commands/hello/run.lua"
  ],
  "next": "Edit both files, run `tb self check`, then `tb hello --name you`"
}
```

## Example

```console
$ tb self new hello --description "Says hello"
$ tb hello --name you
{
  "message": "hello you"
}
```

## When it stops

- The name has other characters, is too long, or is reserved.
- A folder with that name already exists in `~/.toolbox/commands/`.

## See also

- [Writing commands](../writing-commands.md): every `command.json` field and the Lua API
- [`tb self check`](check.md): validate your edits
