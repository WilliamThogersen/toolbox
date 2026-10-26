<!-- Written by `tb self init`. Edits here are replaced: run `tb self init` again after upgrading toolbox. -->
# toolbox (tb)

`tb` is my toolbox CLI: small commands for APIs and tools, with API keys kept in a vault. Reach for it first.
It is how I want APIs called and repeatable tasks done.

## Use a command before anything else
- Run `tb` to list my commands and `tb self describe` for their args and permissions as JSON.
- Before writing curl, a one-off script or an API client, check for a command that does it and run that:
  `tb <name> --<arg> <value>`.
- Nothing fits? Look in my marketplaces with `tb self search <words>` before writing anything.

## Make a command when one is missing
- A task you would script, or do twice, becomes a command.
- Read `tb self guide`, run `tb self new <name>`, edit `command.json` and `run.lua`, then run `tb self check`.
- stdout is only JSON. Errors are `{"error": ...}` on stderr with exit code 1.

## API keys
- Keys live in the vault. In a script, `vault("name")` goes in a header or `query` value: you never see the key.
- Never ask me for a key, and never put one in a file, an env var or a command line.
- Missing key: run `tb self vault request <name> --host <host> --why "<what for>"`, then ask me to run
  `tb self vault setup`.
- A command not allowed to use a key: the error says what to ask me to run.
- A request I didn't confirm with Touch ID: don't retry it unless I ask.
- An API that signs in with OAuth (Google, Microsoft, Slack): ask me to run `tb self vault oauth <name>` (see `tb self guide`).

## Installing
- Before `tb self install <source> --yes`, show me the permissions it lists and wait for my OK.
