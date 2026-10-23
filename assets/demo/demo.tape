# Records assets/demo.gif. Run from the repo root:
#   cargo build --release && vhs assets/demo/demo.tape
#
# It uses a throwaway home in /tmp/toolbox-demo and the plain-text test vault,
# so the Keychain and your own commands are never touched. The demo key is fake.
# The `hello` command is made with `tb self new` and given a shorter run.lua, and
# `peek` is added and allowed to use the key after the key is stored, both off camera.
# The last scene calls https://httpbin.org, so it needs the network.

Output assets/demo.gif

Require bash

Set Shell "bash"
Set FontSize 22
Set LineHeight 1.3
Set Width 1000
Set Height 520
Set Padding 40
Set TypingSpeed 38ms
Set CursorBlink false
Set WindowBar Colorful
Set Theme { "name": "toolbox", "background": "#1C1917", "foreground": "#F5F5F4", "selection": "#44403C", "cursor": "#F97316", "black": "#1C1917", "brightBlack": "#78716C", "red": "#F87171", "brightRed": "#FCA5A5", "green": "#86EFAC", "brightGreen": "#BBF7D0", "yellow": "#FDBA74", "brightYellow": "#FED7AA", "blue": "#93C5FD", "brightBlue": "#BFDBFE", "magenta": "#F0ABFC", "brightMagenta": "#F5D0FE", "cyan": "#67E8F9", "brightCyan": "#A5F3FC", "white": "#E7E5E4", "brightWhite": "#FAFAF9" }

Hide
Type "export TOOLBOX_HOME=/tmp/toolbox-demo TOOLBOX_INSECURE_TEST_VAULT=/tmp/toolbox-demo/vault.json TOOLBOX_NO_UPDATE_CHECK=1" Enter
Type "rm -rf /tmp/toolbox-demo && mkdir -p /tmp/toolbox-demo/bin /tmp/toolbox-demo/commands" Enter
Type `ln -s "$PWD/target/release/toolbox" /tmp/toolbox-demo/bin/tb && cp -R assets/demo/peek /tmp/toolbox-demo/` Enter
Type `export PATH="/tmp/toolbox-demo/bin:$PATH" PS1='\[\e[38;2;249;115;22m\]$\[\e[0m\] '` Enter
Type `cd /tmp/toolbox-demo/commands && tb self new hello --description "Says hello" > /dev/null` Enter
Type `printf 'return function(args)\n  return { message = "hello " .. args.name }\nend\n' > hello/run.lua` Enter
Type "clear" Enter
Show

# 1. A command is two files
Type "# A command is a folder with two files" Enter
Sleep 700ms
Type "ls hello" Sleep 300ms Enter
Sleep 1.2s
Type "cat hello/run.lua" Sleep 300ms Enter
Sleep 2s
Type "tb hello --name you" Sleep 300ms Enter
Sleep 2.5s

Hide
Type "clear" Enter
Show

# 2. Store a key once
Type "# Store an API key once. It's typed, never shown." Enter
Sleep 700ms
Type "tb self vault add demo --host httpbin.org" Sleep 300ms Enter
Wait+Screen /input is hidden/
Sleep 800ms
Type@25ms "sk-demo-not-a-real-key"
Sleep 300ms
Enter
Sleep 2.5s

# Off camera: peek arrives, and you read its script and allow it to use the key
Hide
Type "clear && mv ../peek ." Enter
Type "tb self vault allow demo peek" Enter
Sleep 2s
Type "y" Enter
Sleep 500ms
Type "clear" Enter
Show

# 3. The script never holds the key
Type "# peek sends the key to httpbin, which echoes it back" Enter
Sleep 700ms
Type "tb peek" Sleep 300ms Enter
Wait+Screen@20s /server_echoed/
Sleep 2s
Type "# The script got a placeholder. The echo is redacted." Enter
Sleep 3.5s
