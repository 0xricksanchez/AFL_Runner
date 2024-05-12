#!/usr/bin/env vhs 

Output ./img/gen.gif

Require ./target/release/aflr
Require bash
Require echo

# https://github.com/charmbracelet/vhs/blob/main/THEMES.md
Set Theme "Catppuccin Mocha"
Set Framerate 120
Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 600
Set Padding 1

Type "echo 'Create best-practice multi-process AFL++ campaigns effortless from the CLI...'" Sleep 100ms Enter Enter
Sleep 2s

Type "echo 'Exported AFL_* environment variables that are *not set* by AFL_Runner are kept!'" Sleep 100ms Enter
Type "export AFL_PRELOAD=/tmp/mySharedLib.so" Sleep 100ms Enter
Sleep 1s
Type "echo 'Exported AFL_* environment variables that we set explicitly are ignored!'" Sleep 100ms Enter
Type "export AFL_IGNORE_SEED_PROBLEMS=1" Sleep 100ms Enter Enter
Sleep 2s
Type "./target/release/aflr gen -t /tmp/test_bins/target -s /tmp/test_bins/target_asan -c /tmp/test_bins/target_cmplog -l /tmp/test_bins/target_cmpcov -n 8 -i /tmp/seed_corpus -o /tmp/afl_out -x /tmp/fuzzing.dict -- 'arg1 arg2 --arg3 --arg4 @@'" Sleep 100ms Enter Enter
Sleep 4s
Type "clear" Enter
Type "echo '...or save campaign setups in a TOML configuration file for later re-use!'" Sleep 100ms Enter Enter
Type "./target/release/aflr gen --config ../test.toml" Sleep 100ms Enter Enter
Sleep 2s
Type "echo 'Voila! AFLR has generated the best possible multi-process fuzzing setup based on your needs.'" Sleep 100ms Enter
Sleep 4s
