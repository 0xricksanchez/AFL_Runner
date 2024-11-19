#!/usr/bin/env vhs 

Output ./img/cov.gif

Require ./target/release/aflr
Require bash
Require echo
Require w3m
Require head
Require tail

# https://github.com/charmbracelet/vhs/blob/main/THEMES.md
Set Theme "Catppuccin Mocha"
Set Framerate 60
Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 640
Set Padding 1

Type "echo 'This showcases a basic coverage collection with AFLR'" Sleep 100ms Enter
Sleep 2s

Type "echo 'Let us assume we have a long-running campaign already...'" Sleep 100ms Enter
Sleep 2s

Type "echo 'We can collect and create a HTML-based coverage report as easy as:'" Sleep 100ms Enter
Sleep 2s
Type "./target/release/aflr cov -t examples/xmllint_coverage_2.10.0 -i /tmp/afl_out/  -- --memory --noenc --nocdata --dtdattr --loaddtd --valid --xinclude @@" Sleep 100ms Enter
Sleep 2s
Type "echo '...and e.g. view the HTML-based coverage report in the terminal.'" Sleep 100ms Enter
Sleep 2s
Type "w3m -dump -cols 10 -r /tmp/afl_out/coverage_html/index.html | tail -n +15 | head -n 83" Sleep 100ms Enter
Sleep 3s
Type "clear" Sleep 100ms Enter
Type "echo 'Alternatively, we can also just produce a text-based report'" Sleep 100ms Enter
Sleep 2s
Type "./target/release/aflr cov -t examples/xmllint_coverage_2.10.0 -i /tmp/afl_out/ --text-report -- --memory --noenc --nocdata --dtdattr --loaddtd --valid --xinclude @@ | tail -n 5" Sleep 100ms Enter
Sleep 4s
