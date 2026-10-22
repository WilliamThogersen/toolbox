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
    "env":   ["HOME"],
    "read":  ["~/notes"],
    "write": ["."]
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
  - `read`: folders it may read with `fs`, including everything below them.
  - `write`: folders it may create, change and delete files in with `fs` (and read).
    For both, `~` is the home folder and a relative path like `"."` is the folder
    `tb` runs in. Ask for the narrowest folder that works.

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
globals below (`fs` for files, `time` instead of `os.time` and `os.date`).

Lua 5.5 dropped some older functions: write `x ^ y` (not `math.pow`),
`math.atan(y, x)` (not `math.atan2`) and `math.log(x, 10)` (not `math.log10`).
A `for` loop variable can't be assigned to: copy it into a `local` first.

## Globals

### http

```lua
local res = http.get(url, opts)      -- also http.post, http.put, http.patch, http.delete
local res = http.request{ method = "POST", url = url, headers = {...}, json = {...} }
```

`opts` fields:

- `headers`: table.
- `query`: table added to the URL's query string. `{ q = "a b", page = 2 }` sends `?page=2&q=a+b`.
- One body at most: `body` (string), `json` (table, sets `content-type: application/json`)
  or `form` (table, sent as `application/x-www-form-urlencoded`).
- `timeout`: seconds, default 30.

`query` and `form` values are strings, numbers, booleans or lists of those
(`tag = {"a", "b"}` sends `tag=a&tag=b`).

The response is `{ status = 200, headers = {...}, body = "raw text", json = table or nil }`.
Header names are lowercase. `json` is set when the body is JSON. A 4xx or 5xx
status is not an error: check `res.status`. Network failures and timeouts raise an error.

### json

`json.encode(value)` returns a string. `json.decode(text)` returns a value.
JSON `null` decodes to `nil`. Use `json.null` to output an explicit null.

### exec

```lua
local out = exec("git", { "status", "--short" })
-- out = { ok = true, code = 0, stdout = "...", stderr = "..." }

local out = exec("jq", { ".name" }, {
  stdin = json.encode(data),  -- text sent to the program's stdin
  cwd = "/path/to/repo",      -- folder it runs in
  env = { NO_COLOR = "1" },   -- extra environment variables
  timeout = 10,               -- seconds; then it and all it started are killed, and exec raises an error
})
```

No shell: pass args as a list. The program must be in `permissions.exec`. A
non-zero exit is not an error: check `out.ok`.

### fs

```lua
local text = fs.read("notes/today.md")         -- the whole file as a string
fs.write("out/report.json", json.encode(r))    -- creates or replaces the file
fs.append("out/log.txt", "one line\n")
fs.mkdir("out/2026")                            -- parent folders too
fs.exists("notes/today.md")                     -- true or false
fs.list("notes")   -- { { name = "a.md", type = "file", size = 120 }, ... }, sorted by name
fs.remove("out/old.json")                       -- a file, a symlink or an empty folder
```

Paths are absolute, `~/...`, or relative to the folder `tb` runs in. Reading needs
the path inside a `permissions.read` or `permissions.write` folder. Writing,
`mkdir` and `remove` need `permissions.write`. Symlinks are followed before the
check, so a link can't lead outside. `fs.write` does not create folders: call
`fs.mkdir` first. Files over 20 MB can't be read. `type` is `file`, `dir`,
`symlink` or `other`.

### stdin

`stdin.read()` returns everything piped into the command (`cat data.csv | tb import`),
or `nil` when stdin is a terminal. No permission needed.

### time

```lua
local t = time.now()                       -- 1792654200.123: seconds since 1970, UTC
time.format(t)                             -- "2026-10-22T07:30:00Z"
time.format(t, "%d/%m/%Y %H:%M", "local")  -- strftime format, zone "utc" (default) or "local"
time.format()                              -- now
time.parse("2026-10-22T09:30:00+02:00")    -- also "2026-10-22" and HTTP dates
time.parse("22.10.2026", "%d.%m.%Y")       -- with a format; no zone in it means UTC
time.sleep(1.5)                            -- seconds
```

Times are numbers with milliseconds: use `math.floor(t)` for whole seconds.

### base64, url, hash

```lua
base64.encode("text")             -- "dGV4dA=="
base64.decode("dGV4dA==")         -- padding optional
base64.encode(data, "url")        -- URL-safe alphabet, no padding (JWTs); decode takes "url" too
url.encode("a b/c")               -- "a%20b%2Fc": safe as one path segment or value
url.decode("a%20b")               -- "a b"
url.query({ q = "a b", page = 2 }) -- "page=2&q=a+b"
hash.sha256("text")               -- hex; pass "base64" or "raw" as 2nd arg for other output
hash.hmac_sha256(key, message)    -- hex; "base64" or "raw" as 3rd arg
```

They refuse vault placeholders: a key only ever goes straight into an http header
value, so a script can't encode, hash or sign with it.

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
single command with both files at the repo root. Other files are ignored. A
repo with many commands works as a marketplace.

- `tb self search <words>` searches every marketplace the user saved. Check it
  before writing a new command. Results are JSON with `market`, `name`,
  `description`, `permissions` and `installed`.
- `tb self install acme/stars` installs `stars` from the saved marketplace
  `acme`. `tb self install <git-url> stars pr-status` picks commands from any
  repo; without names it installs every working command and skips broken ones.
  `--list` shows a repo's commands without installing. `--ref <branch|tag|commit>`
  picks a version.
- Without a terminal it stops and lists each command's permissions. Show that list
  to the user and wait for their OK before running it again with `--yes`.
- `tb self update [<name>]` takes newer versions. With a `version`, only a higher
  one counts. Without one, any new commit counts. Every update asks first, so
  without a terminal it stops and lists the changes: show them to the user and
  wait for their OK before `--yes`.
- `tb self uninstall <name>` removes an installed command. Commands made locally
  are never removed by it.
- `tb self market add <name> <git-url>` saves a marketplace, `tb self market list`
  shows them, `tb self market rm <name>` forgets one. Ask the user before adding one.

To publish a new version: bump `version` in `command.json`, commit, push.
