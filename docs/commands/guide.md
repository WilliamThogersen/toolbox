# tb self guide

Prints the reference for writing commands: the `command.json` format, the Lua API, the vault and sharing.

```
tb self guide
```

No arguments.

## What it does

Prints [Writing commands](../writing-commands.md) as Markdown. The text is built into the binary, so it always
matches the toolbox version you have installed.

This is the only `tb self` command whose output is not JSON. It is meant to be read, usually by an AI agent before
it writes a new command.

## See also

- [Writing commands](../writing-commands.md): the same text, on GitHub
- [`tb self new`](new.md): start a command from a template
