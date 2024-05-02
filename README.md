# AFL Runner

[![Crates.io](https://img.shields.io/crates/v/afl_runner.svg)](https://crates.io/crates/afl_runner)
[![License](https://img.shields.io/badge/license%20-%20Apache%202.0%20-%20blue)](LICENSE)

`AFL_Runner` is a modern CLI tool designed to streamline running efficient multi-core [AFLPlusPlus](https://github.com/AFLplusplus/AFLplusplus) campaigns. The default configuration is based on the section [_Using multiple cores_](https://aflplus.plus/docs/fuzzing_in_depth/#c-using-multiple-cores) of the official documentation.

## Getting Started 🚀

Currently, this tool should work on all \*NIX flavor operating-systems.

### Prerequisites

- [Rust (nightly) toolchain](https://www.rust-lang.org/tools/install) 🦀
- [AFLPlusPlus](https://github.com/AFLplusplus/AFLplusplus)
- [pgrep](https://man7.org/linux/man-pages/man1/pgrep.1.html)
- [TMUX](https://github.com/tmux/tmux) || [screen](https://www.gnu.org/software/screen/) (Optional)

### Installation

You can compile `AFL_Runner` yourself:

```bash
git clone https://github.com/0xricksanchez/AFL_Runner.git alfrunner
cd alfrunner
cargo build --release
./target/release/aflr --help
```

Or install via [crates.io](https://crates.io/crates/afl_runner):

```bash
cargo install afl_runner
aflr --help
```

## Features ✨

`AFL_Runner` allows you to set the most necessary AFLPlusplus flags and mimics the AFLplusplus syntax for these options:

- Supported AFLplusplus flags:

  - [x] Corpus directory
  - [x] Output directory
  - [x] Dictionary file
  - [x] Custom `afl-fuzz` binary path for all instances
  - [x] Supply arguments to target binary (including @@)
  - [x] Amount of runner commands to generate
  - [x] Support for \*SAN, CMPLOG, CMPCOV binaries

- Other features:
  - [x] `Tmux` or `screen` option to automatically create an appropriate layout for all runners
  - [x] TUI
  - [x] Provide a configuration file via `--config` to make sharing/storing per project configurations easier
    - [x] Automatically read out a configuration named `aflr_cfg.toml` in the `CWD` when no `--config` was supplied

_Note_: Arguments supplied over the command-line take precedence over any configuration file options.

## Roadmap 🗺️

- [ ] Add remote option 🌐
- [ ] Integrate [statsd](https://registry.hub.docker.com/r/prom/statsd-exporter)
- [ ] Add more sensible defaults for other options
- [ ] Add more configuration options
- [ ] Allow AFLPlusPlus forks to be used on some amount of runners

## Usage Example 💡

Here's an example of generating AFL++ commands with `AFL_Runner`:

```bash
# Exported AFL_* environment variables that are *not set* by AFL_Runner are kept!
$ export AFL_PRELOAD=/tmp/mySharedLib.so
# Exported AFL_* environment variables that we set explicitly are ignored!
$ export AFL_IGNORE_SEED_PROBLEMS=1
$ aflr gen -t /tmp/test_bins/target -s /tmp/test_bins/target_asan -c /tmp/test_bins/target_cmplog -l /tmp/test_bins/target_cmpcov -n 16 -i /tmp/seed_corpus -o /tmp/afl_out -x /tmp/fuzzing.dict -- 'arg1 arg2 --arg3 --arg4 @@'
Generated commands:
  0. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=0 AFL_EXPAND_HAVOC_NOW=1 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -Z -p fast -i /tmp/seed_corpus -o /tmp/afl_out -M main_target -- /tmp/test_bins/target_asan arg1 arg2 --arg3 --arg4 @@
  1. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=1 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -p explore -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_0_target -l 2 -c /tmp/test_bins/target_cmplog -- /tmp/test_bins/target arg1 arg2 --arg3 --arg4 @@
  2. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=0 AFL_KEEP_TIMEOUTS=1 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -p coe -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_1_target -c /tmp/test_bins/target_cmplog -- /tmp/test_bins/target arg1 arg2 --arg3 --arg4 @@
  3. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=0 AFL_KEEP_TIMEOUTS=0 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -a text -p lin -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_2_target -l 2 -c /tmp/test_bins/target_cmplog -- /tmp/test_bins/target arg1 arg2 --arg3 --arg4 @@
  4. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=0 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -Z -p quad -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_3_target -c /tmp/test_bins/target_cmplog -- /tmp/test_bins/target arg1 arg2 --arg3 --arg4 @@
  5. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=0 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -P explore -a text -Z -p exploit -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_4_target -- /tmp/test_bins/target arg1 arg2 --arg3 --arg4 @@
  6. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=0 AFL_EXPAND_HAVOC_NOW=1 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -P exploit -a text -p rare -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_5_target -- /tmp/test_bins/target arg1 arg2 --arg3 --arg4 @@
  7. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=0 AFL_KEEP_TIMEOUTS=1 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -L 0 -p fast -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_6_target -- /tmp/test_bins/target arg1 arg2 --arg3 --arg4 @@
  8. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=0 AFL_KEEP_TIMEOUTS=0 AFL_EXPAND_HAVOC_NOW=1 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -P explore -a binary -p explore -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_7_target -- /tmp/test_bins/target arg1 arg2 --arg3 --arg4 @@
  9. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=0 AFL_KEEP_TIMEOUTS=0 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -P exploit -a binary -p coe -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_8_target -- /tmp/test_bins/target_cmpcov arg1 arg2 --arg3 --arg4 @@
 10. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=1 AFL_EXPAND_HAVOC_NOW=1 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -P explore -a binary -p lin -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_9_target -- /tmp/test_bins/target_cmpcov arg1 arg2 --arg3 --arg4 @@
 11. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=0 AFL_KEEP_TIMEOUTS=1 AFL_EXPAND_HAVOC_NOW=1 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -a text -p quad -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_10_target -- /tmp/test_bins/target_cmpcov arg1 arg2 --arg3 --arg4 @@
 12. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=1 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -P explore -p exploit -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_11_target -- /tmp/test_bins/target arg1 arg2 --arg3 --arg4 @@
 13. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=0 AFL_EXPAND_HAVOC_NOW=1 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -P exploit -a binary -p rare -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_12_target -- /tmp/test_bins/target arg1 arg2 --arg3 --arg4 @@
 14. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=1 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -P explore -p fast -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_13_target -- /tmp/test_bins/target arg1 arg2 --arg3 --arg4 @@
 15. AFL_PRELOAD=/tmp/mySharedLib.so AFL_AUTORESUME=1 AFL_FINAL_SYNC=1 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=1 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250 /usr/local/bin/afl-fuzz -P explore -p explore -i /tmp/seed_corpus -o /tmp/afl_out -S secondary_14_target -- /tmp/test_bins/target arg1 arg2 --arg3 --arg4 @@
```

_Note_: Supplying the \*SAN, CMPLOG, or CMPCOV binaries are optional and if omitted all invocations just contain the instrumented target instead.

## Showcase 🎥

`AFL_Runner` also includes a terminal user interface (TUI) for monitoring the fuzzing campaign progress:

![AFL_Runner TUI](img/tui.png)

_Note_: The TUI can be used as a **full** replacement for `afl-whatsup` by using `afl_runner tui <afl_output_dir>`!

## Contributing 🤝

Contributions are welcome! Please feel free to submit a pull request or open an issue for any bugs, feature requests, or improvements.

## License 📜

This project is licensed under the Apache License. See the [LICENSE](LICENSE) file for details.
