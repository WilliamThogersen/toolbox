# Code rules

toolbox follows NASA/JPL's ["Power of 10"](https://spinroot.com/gerard/pdf/P10.pdf) rules for safety-critical
code, translated to Rust. The original rules are written for C. Some map one to one, some need a Rust reading, and
one doesn't fit a CLI that runs Lua and talks HTTP. This page says which is which and how each is checked.

Most rules are enforced by lints: the `[lints]` table in `Cargo.toml` and the thresholds in `clippy.toml`. CI runs
`cargo clippy --all-targets -- -D warnings`, so a warning fails the build. A lint is switched off at one place only
with `#[expect(lint, reason = "...")]`, which says why and fails once the lint no longer fires there.

| # | Rule | In toolbox | Checked by |
|---|------|------------|------------|
| 1 | Simple control flow, no recursion | No recursion, direct or mutual. Trees (like JSON bodies) are walked with a list of what's left to visit. No panics as control flow: no `unwrap`, `expect`, `panic!`, `unreachable!` or indexing that can fail outside tests | `unwrap_used`, `expect_used`, `panic`, `unreachable`, `indexing_slicing`, `exit`; recursion by review |
| 2 | Every loop has a provable limit | `for` over a finite collection or range, or a `loop`/`while` with its limit in its condition. The others are listed below with their bound; a new one gets a row there | `infinite_loop`; the list by review |
| 3 | No allocation after start-up | Doesn't fit: every run builds a Lua state, JSON and HTTP requests. Instead, every buffer filled from outside the process has a fixed cap (below) | Tests for each cap |
| 4 | Functions fit on a page | At most 60 lines of code per function | `too_many_lines` (threshold in `clippy.toml`) |
| 5 | Check assumptions | Invariants the types can't hold are checked and turned into an error the caller handles (`ensure!`, `bail!`, `ok_or_else`), never a crash. `debug_assert!` documents a caller's promise in tests and debug builds | Review |
| 6 | Smallest scope | Data lives in the function or struct that needs it. No global mutable state, with one exception: the atomic `EXEC_GROUP` in `src/sys/`, since a signal handler can reach nothing but statics | Review |
| 7 | Check inputs and return values | Inputs are validated where they enter (manifests, key names, hosts, script values). A `Result` is never dropped silently: `let _ =` is the one way to drop one, and each use has its reason in `CLAUDE.md` | `unused_must_use` (rustc); the reasons by review |
| 8 | Little preprocessor use | No `macro_rules!`. The only `#[cfg(target_os)]` is the `compile_error!` in `src/sys/mod.rs` that stops a build outside macOS | Review |
| 9 | Restricted pointer use | `unsafe` only in `src/sys/` (and two small test helpers), each block with a `// SAFETY:` comment (the only comments in `src/`) and one unsafe operation. Raw pointers never leave those functions. The one function pointer handed to C is the signal handler in `src/sys/` | `unsafe_code = "deny"`, `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block` |
| 10 | Strict warnings, zero of them, analysis daily | `clippy::pedantic` plus the lints above, 0 warnings. Dependencies are checked against security advisories every day | CI (`ci.yml`), `cargo deny` (`deny.yml`, daily) |

## Loops whose bound isn't in their condition (rule 2)

| Where | Bound |
|-------|-------|
| `runtime/exec.rs` `finish_within` | The deadline: each turn sleeps at most until it, then returns |
| `runtime/http.rs` `json_has_secret`, `redact_json` | Each value of the parsed body is popped once |
| `vault/inject.rs` `parse`, `vault/unescape.rs` `Unescaped::new` | Each turn moves past what it found, so at most one turn per byte |
| `mcp/mod.rs` `read_messages`, `mcp/lines.rs` `skip_line` | Each turn consumes at least one byte of input; ends at end of input |
| `mcp/mod.rs` `watch` | Meant to run as long as the server; stops when stdout is gone |
| `vault/activity.rs` `Follower::run` | Meant to run until the person presses `Ctrl-C`; stops when stdout is gone |

## Caps on outside input (rule 3)

| What | Cap | Where |
|------|-----|-------|
| `fs.read` file | 20 MB | `runtime::read_capped` |
| `http` response body | 20 MB | `runtime/http.rs` |
| `exec` output, each of stdout and stderr | 20 MB (the rest is drained and dropped, so the program never blocks) | `runtime/exec.rs` |
| `stdin.read()` | 20 MB | `runtime::read_capped` |
| One MCP message | 4 MB | `mcp/lines.rs` |
| Lua memory | 512 MB unless `limits.memory_mb` asks for more | `runtime/limits.rs` |
| Lua CPU time | 60 s unless `limits.cpu_seconds` asks for more. If the CPU clock can't be read, the run fails | `runtime/limits.rs` |
| Waiting on an `exec` program | 10 min unless the script sets `timeout` | `runtime/exec.rs` |
| OAuth token endpoint answer | 1 MB, 30 s | `vault/oauth/token.rs` |
| OAuth sign-in coming back | 5 min in all, 20 visits, 16 KB and 5 s per visit | `vault/oauth/login.rs` |
| Waiting for another run to renew an OAuth token | 40 s | `vault/oauth/cache.rs` |
| OAuth token cache file | 64 KB (bigger reads as no cache) | `vault/oauth/cache.rs` |
| `vault log --follow`, each read | 8 MB | `vault/activity.rs` |

Release builds also keep overflow checks on (`[profile.release]` in `Cargo.toml`), so arithmetic that overflows ends
the run with an error instead of a wrong number.

## What stays allowed

- `clippy::assert_is_empty` is off: its fix (`assert_eq!(x, [] as [T; 0])`) reads worse than `assert!(x.is_empty())`.
- Tests may `unwrap`, `expect`, `panic` and index (`clippy.toml`, and the crate attributes at the top of each file in
  `tests/`): a panic there is a failed test, not a crash.
- clap's `get_one` and `get_flag` panic on a wrong id or type. Code uses `src/cli/matches.rs`, which returns an error.
- No comments in `src/` except `// SAFETY:`. Names carry the what; `CLAUDE.md` ("Why the code is the way it is") and these docs carry the why.
