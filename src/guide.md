# Writing toolbox commands

A command is a folder `<commands_dir>/<name>/` with two files: `command.json`
(what it is) and `run.lua` (what it does). toolbox picks it up on the next run. No
rebuild. `tb self describe` prints `commands_dir`.

1. `tb self new <name> --description "..."` creates both files from a template.
2. Edit `command.json` and `run.lua`.
3. `tb self check` validates every command. Fix every problem it lists.
4. Run it: `tb <name> --some-arg value`.

Output is JSON on stdout. On failure toolbox exits 1 and prints `{"error": "..."}`
on stderr.

## command.json

```json
{
  "name": "pr-status",
  "version": "1.0.0",
  "description": "Show the state of a GitHub pull request",
  "args": {
    "repo":   { "type": "string",  "required": true, "description": "owner/repo" },
    "number": { "type": "integer", "required": true },
    "limit":  { "type": "integer", "default": 10 },
    "draft":  { "type": "boolean", "description": "Flag, true when given" }
  },
  "permissions": {
    "http":  ["api.github.com"],
    "vault": ["github"],
    "exec":  ["git"],
    "env":   ["HOME"]
  }
}
```

- `name` must match the folder name. Allowed: `a-z`, `0-9`, `-`, `_`.
- `version` is optional semver (`1.2.0`). `tb self update` only replaces an
  installed copy when this goes up. `tb self new` starts at `0.1.0`.
- Each arg becomes `--<arg>`. Types: `string`, `integer`, `number`, `boolean`.
  A boolean is a flag: never `required`, defaults to `false`.
- Unknown fields are errors, so typos are caught by `tb self check`.
- `permissions` lists everything the script may touch. Anything not listed fails at runtime.
  - `http`: hosts it may call. `"*"` allows any host.
  - `vault`: secret names it may use (see Vault below).
  - `exec`: programs it may run.
  - `env`: environment variables it may read.

## run.lua

`run.lua` must return one function. It gets the args table. Its return value
is printed as JSON (tables, strings, numbers, booleans, nil).

```lua
return function(args)
  return { hello = args.name }
end
```

Lua 5.5. The standard `string`, `table`, `math`, `utf8` and `coroutine` libraries
are available. `io`, `os`, `require`, `load`, `dofile` are not: use the toolbox
globals below.

Lua 5.5 dropped some older functions: write `x ^ y` (not `math.pow`),
`math.atan(y, x)` (not `math.atan2`) and `math.log(x, 10)` (not `math.log10`).
A `for` loop variable can't be assigned to: copy it into a `local` first.

## Globals

### http

```lua
local res = http.get(url, opts)      -- also http.post, http.put, http.patch, http.delete
local res = http.request{ method = "POST", url = url, headers = {...}, json = {...} }
```

`opts` fields: `headers` (table), `body` (string) or `json` (table, sets
`content-type: application/json`). Use `body` or `json`, not both.

The response is `{ status = 200, headers = {...}, body = "raw text", json = table or nil }`.
Header names are lowercase. `json` is set when the body is JSON. A 4xx or 5xx
status is not an error: check `res.status`. Network failures raise an error.
Timeout is 30 seconds.

### json

`json.encode(value)` returns a string. `json.decode(text)` returns a value.
JSON `null` decodes to `nil`. Use `json.null` to output an explicit null.

### exec

```lua
local out = exec("git", { "status", "--short" })
-- out = { ok = true, code = 0, stdout = "...", stderr = "..." }
```

No shell: pass args as a list. The program must be in `permissions.exec`.

### env

`env.get("NAME")` returns the value or `nil`. The name must be in `permissions.env`.

### log / print

`log(...)` and `print(...)` write to stderr. stdout is reserved for the result.

### Errors

`error("message")` stops the command and toolbox exits 1. Use `pcall` to recover.

## Vault: API keys you can use but never see

The human stores keys in the OS keychain. Your script never receives a value.
`vault("name")` returns a placeholder, and toolbox swaps in the real key only while
sending the request:

```lua
local res = http.get("https://api.github.com/user", {
  headers = { Authorization = "Bearer " .. vault("github") }
})
```

Rules:

1. The secret must be listed in `permissions.vault`.
2. Placeholders work only in header values. In the URL or body they raise an error.
3. The request must go to a host the human allowed for that secret, over https
   (plain http is allowed for localhost only).
4. Requests that carry a secret never follow redirects.
5. Any secret value that appears in a response is replaced with `[REDACTED:<name>]`.

`tb self vault list` shows which secrets exist and where they may be sent. If a
secret is missing, ask the user to run `tb self vault add <name> --host <host>` in
their own terminal. You cannot add, change or read secrets yourself.

## Full example

`run.lua` for the `pr-status` manifest above:

```lua
return function(args)
  local res = http.get(
    "https://api.github.com/repos/" .. args.repo .. "/pulls/" .. args.number,
    { headers = {
        Authorization = "Bearer " .. vault("github"),
        Accept = "application/vnd.github+json",
        ["User-Agent"] = "toolbox",
    } }
  )
  if res.status == 404 then error("PR not found") end
  if res.status ~= 200 then error("GitHub returned " .. res.status .. ": " .. res.body) end

  local pr = res.json
  if pr.merged then
    return { state = "merged", by = pr.merged_by and pr.merged_by.login }
  end
  return { state = pr.state, draft = pr.draft, mergeable = pr.mergeable }
end
```

## Sharing commands through git

Any git repo (GitHub, GitLab, self-hosted) can hold commands: one folder per
command at the top level (`<repo>/<name>/command.json` and `run.lua`), or a
single command with both files at the repo root. Other files are ignored.

- `tb self install <git-url>` installs every command in the repo, or none if
  any is broken or its name is taken. `--ref <branch|tag|commit>` picks a version.
- Without a terminal it stops and lists each command's permissions. Show that list
  to the user and wait for their OK before running it again with `--yes`.
- `tb self update [<name>]` takes newer versions. With a `version`, only a higher
  one counts. Without one, any new commit counts. Every update asks first, so
  without a terminal it stops and lists the changes: show them to the user and
  wait for their OK before `--yes`.
- `tb self uninstall <name>` removes an installed command. Commands made locally
  are never removed by it.

To publish a new version: bump `version` in `command.json`, commit, push.
