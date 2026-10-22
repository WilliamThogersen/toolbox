# tb self market

Saves git repos of commands under a short name, like Homebrew taps. You can then
[search](search.md) them and install as `<market>/<command>`.

```
tb self market add <name> <url> [--ref <ref>]
tb self market list
tb self market rm <name>
```

Saved marketplaces live in `~/.toolbox/markets.json`.

## tb self market add

Saves a marketplace.

| Argument | Meaning |
|----------|---------|
| `<name>` | Short name, used as `<name>/<command>`. `a-z`, `0-9`, `-`, `_`. |
| `<url>` | Git URL (any host, HTTPS or SSH) or local repo path. |
| `--ref <ref>` | Follow this branch or tag instead of the default branch. |

It fetches the repo once, so a wrong URL fails right away. It runs nothing and installs nothing.

```json
{ "name": "acme", "url": "https://github.com/acme/tb-market.git", "commands": ["pr-status", "stars"] }
```

Stops when the name is taken (remove the old one first), the repo can't be fetched, or it has no commands.

## tb self market list

```json
[
  { "name": "acme", "url": "https://github.com/acme/tb-market.git" },
  { "name": "tools", "url": "git@gitlab.com:me/tools.git", "ref": "stable" }
]
```

## tb self market rm

Forgets a marketplace.

| Argument | Meaning |
|----------|---------|
| `<name>` | The marketplace to forget. |

Commands installed from it stay, and [`tb self update`](update.md) keeps updating them from its URL. Use
[`tb self uninstall`](uninstall.md) to remove them.

```json
{ "name": "acme", "removed": true }
```

## Example

```console
$ tb self market add acme https://github.com/acme/tb-market.git
$ tb self search github
$ tb self install acme/stars
$ tb self install acme pr-status weather
```

## See also

- [Sharing commands](../sharing.md#run-a-marketplace): make your own marketplace
