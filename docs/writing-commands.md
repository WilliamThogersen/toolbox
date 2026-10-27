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
    "write": ["."],
    "terminal": true,
    "background": true
  },
  "limits": { "cpu_seconds": 120, "memory_mb": 1024 }
}
```

- `name` must match the folder name. Allowed: `a-z`, `0-9`, `-`, `_`.
- `version` is optional semver (`1.2.0`). `tb self update` only replaces an
  installed copy when this goes up. `tb self new` starts at `0.1.0`.
- Each arg becomes `--<arg>`. Types: `string`, `integer`, `number`, `boolean`.
  A boolean is a flag: never `required`, defaults to `false`.
- Unknown fields are errors, so typos are caught by `tb self check`.
- `permissions` lists everything the script may touch. Anything not listed fails at runtime.
  - `http`: hosts it may call, also when following a redirect. `"*"` allows any host.
  - `vault`: secret names it may use, or patterns like `github/*` (see Vault below).
  - `exec`: programs it may run.
  - `env`: environment variables it may read.
  - `read`: folders it may read with `fs`, including everything below them.
  - `write`: folders it may create, change and delete files in with `fs` (and read).
    For both, `~` is the home folder and a relative path like `"."` is the folder
    `tb` runs in. Ask for the narrowest folder that works.
  - `terminal`: `true` lets it ask the person questions (`prompt`) and hand them a
    program (`exec` with `terminal = true`). Only when a person runs it in a terminal.
    (A program `exec` runs can always open the terminal itself, as `ssh` and `sudo`
    do to ask for passwords: this flag is what lets the script itself talk to you.)
  - `background`: `true` lets `exec` start programs that keep running after the
    command ends (`detach = true`).
- `limits` is optional. Without it a run may use 60 seconds of CPU time and 512 MB
  of memory for Lua values, so a runaway loop ends with an error instead of hanging.
  Raise them only if the command needs it: `cpu_seconds` (up to 86400) and
  `memory_mb` (up to 65536). Waiting for `http` or `exec` uses no CPU time. A script
  that catches the CPU-time error with `pcall` and keeps going is stopped anyway.

## run.lua

`run.lua` must return one function. It gets the args table. Its return value
is printed as JSON (tables, strings, numbers, booleans, nil).

```lua
return function(args)
  return { hello = args.name }
end
```

Lua 5.5. The standard `string`, `table`, `math`, `utf8` and `coroutine` libraries
are available. `io`, `os`, `load`, `dofile` are not: use the toolbox
globals below (`fs` for files, `time` instead of `os.time` and `os.date`).
`require` only loads the command's own `lib/` files (see
[Subcommands and shared code](#subcommands-and-shared-code)).

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
status is not an error: check `res.status`. Network failures, timeouts and bodies over
20 MB raise an error.
Up to 10 redirects are followed, each only to a host in `permissions.http`: a redirect to
any other host raises an error, so list every host the API sends you to.

### json

`json.encode(value)` returns a string. `json.decode(text)` returns a value.
JSON `null` decodes to `nil`. Use `json.null` to output an explicit null.

### yaml

`yaml.encode(value)` returns a string. `yaml.decode(text)` returns a value. YAML
`~` and `null` decode to `nil`. One document per string, at most 4 MB; anchors that
would blow up into a huge value are an error.

### exec

```lua
local out = exec("git", { "status", "--short" })
-- out = { ok = true, code = 0, stdout = "...", stderr = "..." }

local out = exec("jq", { ".name" }, {
  stdin = json.encode(data),  -- text sent to the program's stdin
  cwd = "/path/to/repo",      -- folder it runs in
  env = { NO_COLOR = "1" },   -- extra environment variables (see below for what's refused)
  timeout = 10,               -- seconds (default 600); then it and all it started are killed, and exec raises an error
})
```

No shell: pass args as a list. The program must be in `permissions.exec`. A
non-zero exit is not an error: check `out.ok`. Output over 20 MB on stdout or stderr
is an error. toolbox finds the program with its
own `PATH` (a path like `./tool` means the folder `tb` runs in), so `cwd` and `env`
can't swap in another one. `env` can't set `PATH`, `LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`,
`SHELLOPTS`, `BASHOPTS` or `PS4`, since they change which code runs, and names must
not be empty or contain `=`.

The program doesn't get toolbox's whole environment. It gets `PATH`, `HOME`, `USER`,
`LOGNAME`, `LANG`, `LC_*`, `TMPDIR`, `TERM` and `TZ`, plus the variables listed in
`permissions.env` and those you pass in `env`. Nothing else, so a token in your shell
only reaches a program when the command declares it.

Three more ways to run a program, each its own option:

```lua
-- Show its output while it runs (on stderr), and still get it back.
local out = exec("ddev", { "start" }, { stream = true, timeout = 900 })

-- Hand it the terminal: ssh, a shell, an editor. Needs "terminal": true.
local out = exec("ssh", { "-t", "web1" }, { terminal = true })
-- out = { ok = true, code = 0 }, no stdout or stderr: the person saw them

-- Start it and move on: it keeps running after the command ends. Needs "background": true.
local out = exec("caddy", { "run", "--config", "Caddyfile" }, { detach = true, cwd = dir })
-- out = { pid = 12345 }; stop it later with exec("kill", { tostring(pid) })
```

- `stream`: the program's stdout and stderr show on toolbox's stderr as they come,
  so stdout stays the JSON result. Over MCP they come back as log output.
- `terminal`: the program reads the keyboard and writes to the screen. Ctrl-C goes
  to the program, and the script carries on when it ends. It fails when no person
  is at a terminal (an agent's shell, MCP): ask the person to run the command
  themselves. It waits up to 24 hours unless you set `timeout`. Can't be combined
  with `stdin` or `stream`.
- `detach`: the program gets no stdin, its output is dropped, and it runs in a
  session of its own, so Ctrl-C, a timeout or the end of the command don't stop
  it. Can't be combined with `stdin`, `stream` or `timeout`.

### fs

```lua
local text = fs.read("notes/today.md")         -- the whole file as a string
fs.write("out/report.json", json.encode(r))    -- creates or replaces the file
fs.append("out/log.txt", "one line\n")
fs.mkdir("out/2026")                            -- parent folders too
fs.exists("notes/today.md")                     -- true or false
fs.list("notes")   -- { { name = "a.md", type = "file", size = 120 }, ... }, sorted by name
fs.remove("out/old.json")                       -- a file, a symlink or an empty folder
fs.copy("templates/a.yaml", "out/a.yaml")       -- one file; replaces the target
fs.move("out/a.yaml", "out/b.yaml")             -- a file or folder, on the same disk
fs.chmod("out/run.sh", "755")                   -- octal mode as a string
```

Paths are absolute, `~/...`, or relative to the folder `tb` runs in. Reading needs
the path inside a `permissions.read` or `permissions.write` folder. Writing,
`mkdir`, `remove`, `chmod` and both sides of `move` need `permissions.write`
(`copy` reads from a read folder and writes to a write folder). Modes above `777`
(setuid, setgid, sticky) are refused. A folder listed in `permissions.write` can't be
moved or removed itself. Symlinks are followed before the
check, so a link can't lead outside. `fs.write` does not create folders: call
`fs.mkdir` first. Files over 20 MB can't be read. `type` is `file`, `dir`,
`symlink` or `other`.

### stdin

`stdin.read()` returns everything piped into the command (`cat data.csv | tb import`),
or `nil` when stdin is a terminal. More than 20 MB is an error. No permission needed.

### prompt

Needs `"terminal": true`. Asks the person at the terminal and returns the answer:

```lua
local name = prompt.ask("Project name?", "shop")             -- Enter takes the default
local docker = prompt.confirm("Use Docker?", true)           -- true or false; default false
local php = prompt.choose("PHP version?", { "8.2", "8.3" }, "8.3")  -- by number or name
```

Each question starts on a fresh line with the command's name
(`setup asks: Project name? [shop]`), and answers are never hidden. toolbox asks for
keys only in its own `tb self vault` commands, never inside a command, and in a
terminal `print` and `log` show control characters as escapes, so a script can't
dress a prompt up as one of them. Without a person at a terminal (an agent's shell, MCP) a
prompt raises an error. So take every answer as an arg too, and only ask when it's
missing:

```lua
local php = args.php or prompt.choose("PHP version?", { "8.2", "8.3" }, "8.3")
```

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
value or `query` parameter, so a script can't encode, hash or sign with it. For
Basic auth, use `vault("name", "base64")` (see Vault below).

### env

`env.get("NAME")` returns the value or `nil`. The name must be in `permissions.env`.

### log / print

`log(...)` and `print(...)` write to stderr. stdout is reserved for the result.

### Errors

`error("message")` stops the command and toolbox exits 1. Use `pcall` to recover.
The error shows without Lua's stack traceback, with the line it came from:
`PR not found (at run.lua:12)`. Use `error("message", 0)` for a message without
Lua's own `run.lua:12:` prefix.

## Vault: API keys you can use but never see

The human stores keys in the OS keychain. Your script never receives a value.
`vault("name")` returns a placeholder, and toolbox swaps in the real key only while
sending the request:

```lua
local res = http.get("https://api.github.com/user", {
  headers = { Authorization = "Bearer " .. vault("github") }
})
```

Two more forms, for APIs that don't take a bearer token:

```lua
-- Basic auth: the human stores "user:password" as one secret
headers = { Authorization = "Basic " .. vault("jira", "base64") }

-- A key in the query string: only in parameters the human named with --query-param
http.get("https://maps.googleapis.com/maps/api/geocode/json", {
  query = { key = vault("maps"), address = args.address }
})
```

### Several accounts

Keys can sit in folders, up to 3 parts deep: `github/work`, `github/personal`,
`jira/acme/token`. To let one command work with any account, list a pattern
in `permissions.vault`, take the account as an arg and build the name:

```json
"args": { "account": { "type": "string", "default": "personal", "description": "Key under github/" } },
"permissions": { "http": ["api.github.com"], "vault": ["github/*"] }
```

```lua
headers = { Authorization = "Bearer " .. vault("github/" .. args.account) }
```

`*` stands for exactly one part and never the first: `github/*` covers
`github/work` but not `github` or `github/work/token` (use `github/*/token` for
that). The human allows each key on its own: allowing `github/work` does not let the
command use `github/personal`. `tb self vault list` shows which accounts exist.

Rules:

1. The secret must be listed in `permissions.vault`, or covered by a pattern there.
2. Placeholders work only in header values and in `query = {...}` values. In the
   URL string or the body they raise an error.
3. The request must go to a host the human allowed for that secret, over https.
   Plain http is allowed only for this computer, at the exact address and port the
   human set (like `http://127.0.0.1:8080`, never `localhost`).
4. If the human limited the key to some methods or paths (`tb self vault list`
   shows `methods` and `paths`), other requests raise an error before anything is
   sent. A path with an encoded `.`, `/`, `\` or `%`, or a `..;` part, is refused.
5. The human must allow your command, with `tb self vault setup`. The approval
   covers the exact `command.json` and Lua files they saw (`run.lua` or the
   subcommand scripts, plus `lib/`): after any edit, or a new `lib/` file, the
   human has to allow it again.
6. A key with `confirm` makes the human approve each matching request with Touch
   ID. If they say no, the request raises an error and nothing is sent: don't
   retry unless they ask you to.
7. Requests that carry a secret never follow redirects.
8. Any secret value that appears in a response is replaced with `[REDACTED:<name>]`.
9. The vault is macOS only for now: elsewhere `vault()` raises an error that says so.

Keys from an OAuth sign-in (`"oauth"` in `tb self vault list`) work the same way:
`vault("google")` becomes a fresh access token while sending. toolbox renews it
itself. If it says the sign-in expired, ask the human to run
`tb self vault oauth <name>` in their own terminal.

### Getting a key from the human

`tb self vault list` shows which secrets exist, where they may be sent and which
commands may use them. If the key you need isn't there, request it. This needs no
terminal:

```bash
tb self vault request pagespeed --host www.googleapis.com --query-param key \
  --why "Run Lighthouse audits on your sites through Google's PageSpeed API" \
  --note "Get it at https://console.cloud.google.com/apis/credentials"
```

Ask for no more than the command needs: add `--method GET` when it only reads, and
`--path /pagespeedonline` when it only calls part of the API. The human sees and
can change these at `setup`.

Use the exact host the API lives on, and `--query-param` only when the API wants
the key in the query string (otherwise it goes in headers only). `--why` is
required: one line saying what the key is for, in the user's terms. The note is
one line telling them where to get the key, and which scopes or access to pick. Then finish and test the command's
logic, and ask the user to run `tb self vault setup` in their own terminal: they
paste the key and review your command in one go. Ask once, at the end, so they
only review it once. After you edit the command, ask them to run
`tb self vault setup` again.

When a run fails because of the vault, the error says which of these to do. You
cannot add, change, allow or read secrets yourself.

### Keys that need a sign-in (OAuth)

Some APIs (Google, Microsoft, Slack, GitHub Apps) hand out tokens through a
sign-in page instead of a key to paste. Write the command as usual, with
`vault("gmail")` in the header, and ask the human to run the sign-in in their own
terminal. Give them the full command, with the provider's URLs and the scopes your
command needs:

```bash
tb self vault oauth gmail --host gmail.googleapis.com \
  --auth-url https://accounts.google.com/o/oauth2/v2/auth \
  --token-url https://oauth2.googleapis.com/token \
  --client-id <their OAuth app's client id> \
  --scope https://www.googleapis.com/auth/gmail.send \
  --auth-param access_type=offline --auth-param prompt=consent
```

They need an OAuth app (client id, often a client secret) from the provider's
developer console; say where to create it. Then they allow the command with
`tb self vault setup <command>`.

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

## Subcommands and shared code

Related commands can live in one folder as subcommands and share code. A
`notes` command with `tb notes add` and `tb notes list`:

```
notes/
  command.json
  add.lua          the script of `tb notes add`
  list.lua         the script of `tb notes list`
  lib/store.lua    shared: require("store")
```

```json
{
  "name": "notes",
  "version": "1.0.0",
  "description": "Keep short notes in notes.md",
  "subcommands": {
    "add": {
      "description": "Add a note",
      "args": { "text": { "type": "string", "required": true } },
      "permissions": { "write": ["."] }
    },
    "list": {
      "description": "List the notes",
      "permissions": { "read": ["."] }
    }
  }
}
```

`lib/store.lua` returns what it shares:

```lua
local store = { file = "notes.md" }

function store.all()
  if not fs.exists(store.file) then return {} end
  local notes = {}
  for note in fs.read(store.file):gmatch("%- ([^\n]+)") do
    notes[#notes + 1] = note
  end
  return notes
end

return store
```

`add.lua` (`list.lua` is the same with `return store.all()`):

```lua
local store = require("store")

return function(args)
  fs.append(store.file, "- " .. args.text .. "\n")
  return { notes = #store.all() }
end
```

Rules:

- With `subcommands`, the top level has no `args`, `permissions` or `limits`:
  each subcommand has its own `description`, `args`, `permissions` and `limits`.
  Subcommand names follow the command name rules, and `help` is taken.
- Each subcommand runs `<subcommand>.lua` next to `command.json`. There is no
  `run.lua`. `tb notes` alone lists the subcommands.
- Permissions belong to the subcommand that runs. Shared code gets the
  permissions of whichever subcommand called it, so a `lib/` function that
  calls `vault("github")` fails in a subcommand that doesn't list `github`.
- `require("store")` loads `lib/store.lua` from this command's own folder, runs
  it once and returns what it returned (`true` if nothing). Module names follow
  the command name rules: no paths, dots or subfolders, and never another
  command's files. Modules may `require` each other, but not in a loop.
- A plain command can have a `lib/` folder too.
- The vault approval covers `command.json` and every Lua file together:
  editing any of them, or adding a `lib/` file, needs a new approval for the
  whole command.
- An error names the file it came from: `broke (at lib/store.lua:4)`.
- At most 256 Lua files, 20 MB in all. They must be plain files, not symlinks.
- Over MCP each subcommand is its own tool, named `notes_add` and `notes_list`.

## Sharing commands through git

Any git repo (GitHub, GitLab, self-hosted) can hold commands: one folder per
command at the top level (`<repo>/<name>/command.json` and its Lua files), or a
single command at the repo root. Installing copies `command.json`, the scripts
(`run.lua` or one per subcommand) and `lib/*.lua`. Other files are ignored. A
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
