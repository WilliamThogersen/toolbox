# tb self search

Searches the commands in every saved marketplace.

```
tb self search [<text>]
```

| Argument | Meaning |
|----------|---------|
| `<text>` | Words to look for in command names and descriptions, ignoring case. Default: list everything. |

## What it does

1. Fetches each marketplace saved with [`tb self market add`](market.md). Every search fetches fresh, so results
   are never out of date. That is one quick git fetch per marketplace.
2. Keeps the working commands whose name or description contains `<text>`.

Broken commands are left out. To see them, run `tb self install <marketplace> --list`.

## Output

```json
{
  "results": [
    {
      "market": "acme",
      "name": "stars",
      "version": "1.0.0",
      "description": "Star count for a GitHub repo",
      "permissions": { "http": ["api.github.com"], "vault": [], "exec": [], "env": [] },
      "installed": false
    }
  ],
  "problems": [
    { "command": "tools", "problem": "could not fetch https://...: ..." }
  ]
}
```

- `installed`: already installed from that marketplace.
- `problems`: marketplaces that couldn't be fetched. The others are still searched, and the exit code is `0`.

Install a result with `tb self install <market>/<name>`.

## Example

```console
$ tb self search github
$ tb self install acme/stars
```

## When it stops

- No marketplaces are saved yet. Add one with `tb self market add <name> <git-url>`.

## See also

- [`tb self market`](market.md), [`tb self install`](install.md)
