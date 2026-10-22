# tb self uninstall

Removes a command that was added with [`tb self install`](install.md).

```
tb self uninstall <name>
```

| Argument | Meaning |
|----------|---------|
| `<name>` | The installed command to remove. |

## What it does

Deletes `~/.toolbox/commands/<name>/`, but only when it has a `.source.json`, which means it was installed.

Commands you made yourself are never deleted by it, so an agent can't remove your work by mistake. To remove one of
those, delete its folder yourself.

## Output

```json
{ "name": "stars", "uninstalled": true }
```

## When it stops

- There is no command with that name.
- The command was made locally, not installed.

## See also

- [`tb self install`](install.md)
