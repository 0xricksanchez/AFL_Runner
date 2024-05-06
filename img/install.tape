#!/usr/bin/env vhs 

Output ./img/install.gif

Require cargo
Require bash
Require echo

# https://github.com/charmbracelet/vhs/blob/main/THEMES.md
Set Theme "Catppuccin Mocha"
Set Framerate 120
Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 480
Set Padding 1

Type "echo 'Installing AFL_Runner is as easy as...'" Sleep 100ms Enter
Type "cargo install afl_runner" Sleep 100ms Enter
Sleep 35s
Type "aflr --help" Sleep 100ms Enter Enter
Sleep 2s
Type "echo 'Or you can build it from source...'" Sleep 100ms Enter Enter
Type "cd /tmp/" Sleep 500ms Enter
Type "git clone https://github.com/0xricksanchez/AFL_Runner.git aflrunner" Sleep 100ms Enter
Sleep 2s
Type "cd aflrunner" Sleep 200ms Enter
Type "cargo build" Sleep 100ms Enter
Sleep 12s
Type "./target/debug/aflr --help" Sleep 100ms Enter
Sleep 2s
