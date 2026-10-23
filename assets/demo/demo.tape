# Records assets/demo.gif. Run from the repo root:
#   cargo build --release && vhs assets/demo/demo.tape
#
# It uses a throwaway home in /tmp/toolbox-demo and the plain-text test vault,
# so the Keychain and your own commands are never touched. The demo key is fake.
# The last scene calls https://httpbin.org, so it needs the network.

Output assets/demo.gif

Require bash

Set Shell "bash"
Set FontSize 16
Set Width 1080
Set Height 640
Set Padding 24
Set TypingSpeed 35ms
Set CursorBlink false
Set WindowBar Colorful
Set Theme { "name": "toolbox", "background": "#1C1917", "foreground": "#F5F5F4", "selection": "#44403C", "cursor": "#F97316", "black": "#1C1917", "brightBlack": "#78716C", "red": "#F87171", "brightRed": "#FCA5A5", "green": "#86EFAC", "brightGreen": "#BBF7D0", "yellow": "#FDBA74", "brightYellow": "#FED7AA", "blue": "#93C5FD", "brightBlue": "#BFDBFE", "magenta": "#F0ABFC", "brightMagenta": "#F5D0FE", "cyan": "#67E8F9", "brightCyan": "#A5F3FC", "white": "#E7E5E4", "brightWhite": "#FAFAF9" }

Hide
Type "export TOOLBOX_HOME=/tmp/toolbox-demo TOOLBOX_INSECURE_TEST_VAULT=/tmp/toolbox-demo/vault.json TOOLBOX_NO_UPDATE_CHECK=1" Enter
Type "rm -rf /tmp/toolbox-demo && mkdir -p /tmp/toolbox-demo/bin /tmp/toolbox-demo/commands" Enter
Type `ln -s "$PWD/target/release/toolbox" /tmp/toolbox-demo/bin/tb && cp -R assets/demo/peek /tmp/toolbox-demo/commands/` Enter
Type `export PATH="/tmp/toolbox-demo/bin:$PATH" PS1='\[\e[38;2;249;115;22m\]$\[\e[0m\] '` Enter
Type "clear" Enter
Show

Type "# A command is a folder: command.json + run.lua" Enter
Sleep 600ms
Type `tb self new hello --description "Says hello"` Sleep 300ms Enter
Sleep 2s
Type "tb hello --name you" Sleep 300ms Enter
Sleep 2.5s

Hide
Type "clear" Enter
Show

Type "# API keys: you store them, commands use them, scripts never see them" Enter
Sleep 600ms
Type "tb self vault add demo --host httpbin.org" Sleep 300ms Enter
Wait+Screen /input is hidden/
Sleep 800ms
Type "sk-demo-not-a-real-key"
Enter
Sleep 2s

Hide
Type "clear" Enter
Show

Type "# You read the script once and allow it" Enter
Sleep 600ms
Type "tb self vault allow demo peek" Sleep 300ms Enter
Wait+Screen /\[y\/N\]/
Sleep 4s
Type "y"
Sleep 300ms
Enter
Sleep 2s

Hide
Type "clear" Enter
Show

Type "# The script only ever holds a placeholder." Enter
Type "# httpbin gets the real key and echoes it back. toolbox redacts the echo." Enter
Sleep 600ms
Type "tb peek" Sleep 300ms Enter
Wait+Screen@20s /server_echoed/
Sleep 5s
