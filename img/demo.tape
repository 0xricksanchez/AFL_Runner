#!/usr/bin/env vhs 

Output ./img/demo.gif

Require ./target/release/aflr
Require bash
Require echo
Require tmux

# https://github.com/charmbracelet/vhs/blob/main/THEMES.md
Set Theme "Catppuccin Mocha"
Set Framerate 60
Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 1000
Set Padding 1

Type "echo 'This demo showcases how to quickly spin up 16 AFL++ instances with AFLR.'" Sleep 100ms Enter
Sleep 2s


Type "cargo make" Sleep 100ms Enter
Sleep 30s
Type "q" Sleep 100ms Enter
Sleep 2s
Type "clear" Sleep 100ms Enter
Sleep 1s
Type "echo 'We can always exit the TUI by pressing >q<.'" Sleep 100ms Enter
Sleep 2s
Type "echo 'This does *not* terminate the AFL++ instances, only the TUI.'" Sleep 100ms Enter
Sleep 2s
Type "echo 'To demonstrate this, let us quicky attach to the custom TMUX session...'" Sleep 100ms Enter
Sleep 2s
Type "tmux attach -t aflr_demo_session" Sleep 100ms Enter
Sleep 4s
Ctrl+S
Type n
Sleep 4s
Ctrl+S
Type n
Sleep 4s
Ctrl+S
Type n
Sleep 4s
Ctrl+S
Type d
Type "clear" Sleep 100ms Enter
Type "echo '...and detach from it again.'" Sleep 100ms Enter
Sleep 2s
Type "echo 'Finally, let us terminate the AFL++ instances.'" Sleep 100ms Enter
Sleep 2s
Type "./target/release/aflr kill aflr_demo_session" Sleep 100ms Enter
Sleep 4s
