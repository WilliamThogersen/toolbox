# tb self update

Updates installed commands to the newest version in the repo they came from.

```
tb self update [<name>] [--yes]
```

| Argument | Meaning |
|----------|---------|
| `<name>` | Only update this command. Default: every installed command. |
| `--yes`, `-y` | Don't ask first. Needed when there is no terminal (scripts, AI agents). |

Only commands added with [`tb self install`](install.md) can be updated. Commands you made yourself are skipped.

## What counts as newer

| The installed copy and the repo copy | Updates when |
|--------------------------------------|--------------|
| Both have a `version` | The repo's version is higher (`1.10.0` beats `1.9.0`). Never downgrades. |
| Either has no `version` | The repo has a different commit. |

So an author can push work in progress: users only get it once `version` goes up.

A command installed with `--ref` stays on that ref. A tag or commit therefore never moves, and a branch follows its
new commits. To move to another ref, install again with the new `--ref`.

## What it does

1. Fetches each repo once, even when several commands come from it.
2. Decides per command: newer, up to date, or a problem.
3. If anything is newer, it asks first, every time. New code needs a yes even when the permissions stay the same,
   so a hacked repo can't slip code in on a routine update.
4. Replaces each updated command and its `.source.json`, keeping the marketplace it came from. Local edits to an
   updated command are replaced too.

The prompt:

```console
$ tb self update
Updates:
  stars 1.0.0 -> 1.1.0 from https://gitlab.com/alice/tb-tools.git
    permissions changed
    before: http: api.github.com
    after:  http: api.github.com; exec: git
    ! exec runs git with any arguments. Treat it as full access to your machine
  weather 0.2.0 -> 0.3.0 from https://github.com/acme/tb-market.git
    permissions: http: api.weather.gov
Update 2 commands? [y/N]
```

## Output

```json
{
  "updated": [{ "name": "stars", "from": "1.0.0", "to": "1.1.0" }],
  "up_to_date": ["pr-status"],
  "problems": [{ "command": "gone", "problem": "no longer in https://gitlab.com/alice/tb-tools.git" }]
}
```

- `from` and `to` are versions, or short commits for commands without a version.
- Lists are sorted by name.
- Exit code `1` when `problems` isn't empty. Everything else still updates.

## Problems it reports

- The repo can't be fetched.
- The command is no longer in the repo. The installed copy stays.
- The repo's copy is broken. The installed copy stays.

## See also

- [`tb self install`](install.md)
- [Sharing commands](../sharing.md#releasing-a-new-version): how authors release versions
