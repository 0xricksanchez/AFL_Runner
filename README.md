# AFL Runner

[![Crates.io](https://img.shields.io/crates/v/afl_runner.svg)](https://crates.io/crates/afl_runner)
[![License](https://img.shields.io/badge/license%20-%20Apache%202.0%20-%20blue)](LICENSE)
[![Rust](https://github.com/0xricksanchez/AFL_Runner/actions/workflows/rust.yml/badge.svg)](https://github.com/0xricksanchez/AFL_Runner/actions/workflows/rust.yml)

`AFL_Runner` is a modern CLI tool designed to streamline running efficient multi-core [AFLPlusPlus](https://github.com/AFLplusplus/AFLplusplus) campaigns. The default configuration is based on the section [_Using multiple cores_](https://aflplus.plus/docs/fuzzing_in_depth/#c-using-multiple-cores) of the official documentation.

- [AFL Runner](#afl-runner)
  - [Getting Started 🚀](#getting-started-)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
  - [Features ✨](#features-)
    - [What is not? ❌](#what-is-not-)
    - [Roadmap 🗺️](#roadmap-)
  - [Usage Example 💡](#usage-example-)
    - [Shell Completion ⚡](#shell-completion-)
  - [Showcase 🎥](#showcase-)
  - [Contributing 🤝](#contributing-)
  - [License 📜](#license-)

## Getting Started 🚀

Currently, this tool should work on all \*NIX flavor operating-systems.

### Prerequisites

- [Rust toolchain v1.78.0+](https://www.rust-lang.org/tools/install) 🦀
- [AFLPlusPlus](https://github.com/AFLplusplus/AFLplusplus)
- [pgrep](https://man7.org/linux/man-pages/man1/pgrep.1.html)
- [TMUX](https://github.com/tmux/tmux) || [screen](https://www.gnu.org/software/screen/) (Optional for TUI)
- [LLVM](https://llvm.org/) (Optional for coverage reporting)

### Installation

You can compile `AFL_Runner` yourself...:

```bash
git clone https://github.com/0xricksanchez/AFL_Runner.git
cd AFL_Runner
cargo build --release
./target/release/aflr --help

# Optional: Generate completion scripts
cargo run --features completion --bin generate_completions
```

...or install directly via [crates.io](https://crates.io/crates/afl_runner):

```bash
cargo install afl_runner
aflr --help

# Alternatively, with the completion support included
cargo install --path . --features completion
```

## Features ✨

`AFL_Runner` allows you to set the most necessary AFLPlusplus flags and mimics the AFLplusplus syntax for these options:

- Supported AFLplusplus flags:

  - [x] Corpus directory
  - [x] Output directory
  - [x] Dictionary file/directory
  - [x] Custom `afl-fuzz` binary path for all instances
  - [x] Supply arguments to target binary (including @@)
  - [x] Amount of runner commands to generate
  - [x] Support for \*SAN, CMPLOG, CMPCOV binaries

- Other features:
  - [x] Coverage collection/visualization
  - [x] `Tmux` or `screen` option to automatically create an appropriate layout for all runners
  - [x] TUI
  - [x] Provide a configuration file via `--config` to make sharing/storing per project configurations easier
    - [x] Automatically read out a configuration named `aflr_cfg.toml` in the `CWD` when no `--config` was supplied
  - [x] Mode: `default` (vanilla AFL++), `multiple-cores` ([Ref.](https://aflplus.plus/docs/fuzzing_in_depth/#c-using-multiple-cores)), and `ci-fuzzing` ([Ref.](https://aflplus.plus/docs/fuzzing_in_depth/#5-ci-fuzzing))!
  - [x] _Deterministic_ command generation and AFL++ with seeding

_Note_: Arguments supplied over the command-line take precedence over any configuration file options.

### What is not? ❌

`AFL_Runner` aims to be a plug & play solution for when you're at a stage of fuzzing campaign where all that is left is running a multi-core setup.
So, this tool is **not** (yet) a helper for:

- Compiling a target in multiple flavors
- Preparing a good initial seed corpus
- Providing a decent dictionary to boost code-coverage
- Debugging a fuzzing campaign

### Roadmap 🗺️

- [ ] Add remote option 🌐
- [ ] Native integration for [statsd](https://registry.hub.docker.com/r/prom/statsd-exporter)
- [ ] Add more configuration options
  - [ ] Add more sensible defaults for other options
  - [ ] Full modularity to cater to very specialized fuzzing campaigns
- [ ] Allow AFLPlusPlus forks to be used on some amount of runners

## Usage Example 💡

Here's an example of generating AFL++ commands with `AFL_Runner`:

![AFL_Runner_cmd_gen](img/gen.gif)

_Note_: Supplying the \*SAN, CMPLOG, or CMPCOV binaries is optional and if omitted all invocations just contain the (mandatory) instrumented target instead.

### Shell Completion ⚡

The tool supports shell completion for tmux session names when using the kill command. To enable completion:

1. First generation the completion scripts:

```bash
cargo run --bin generate_completions
```

2. Depending on your shell, do the following:

For ZSH:

```bash
# Option 1: Source directly
source completions/aflr_dynamic.zsh

# Option 2 (preferred): Install to completion directory
mkdir -p ~/.zsh/completions
cp completions/aflr_dynamic.zsh ~/.zsh/completions/_aflr
# Add to your .zshrc:
fpath=(~/.zsh/completions $fpath)
autoload -U compinit && compinit
```

For Bash:

```bash
# Add to your .bashrc:
source /path/to/completions/aflr_dynamic.bash
```

Once set up, you can use tab completion to see available tmux sessions:

```bash
aflr kill <TAB>
```

## Showcase 🎥

`AFL_Runner` also includes a terminal user interface (TUI) for monitoring the fuzzing campaign progress.
The following demo can be found in `examples/` and can be build locally by running `cargo make` from the root directory of the project.

The example builds a recent version of _libxml2_ four times with different compile-time instrumentations:

1. plain AFL++ instrumentation
2. Address-Sanitizer (ASan)
3. CMPCOV,
4. CMPLOG, and
5. Coverage visualization

Afterwards, the necessary commands for 16 instances are being generated, which then are executed in a dedicated TMUX session.
Finally, a custom TUI offered by _AFL Runner_ is tracking the progress of the fuzzing campaign in a centralized space:

![AFL_Runner demo](img/demo.gif)

_Note_: The TUI can be used as a **full** replacement for `afl-whatsup` by using `afl_runner tui <afl_output_dir>`!

Coverage visualization is also covered by `AFL_Runner`:

![AFL_Runner cov](img/cov.gif)

_Note_: IFF you ran the AFLR demo campaign for a while you can run `cargo make afl_coverage` to run the coverage collection as shown above.

## Contributing 🤝

Contributions are welcome! Please feel free to submit a pull request or open an issue for any bugs, feature requests, or improvements.
Any other support is also more than welcome :). Feel to reach out on [X](https://x.com/0xricksanchez) or [BSKY](https://bsky.app/profile/434b.bsky.social).

## License 📜

This project is licensed under the Apache License. See the [LICENSE](LICENSE) file for details.

<br><hr>
[🔼 Back to top](#afl-runner)
