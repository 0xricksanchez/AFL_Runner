## AFLRunner

`AFL_Runner` is a simple CLI tool to make running efficient multi-core [AFLPlusPlus](https://github.com/AFLplusplus/AFLplusplus)
campaigns easier. The default configuration is based on the section [_Using multiple cores_](https://aflplus.plus/docs/fuzzing_in_depth/#c-using-multiple-cores)
of the official documentation.

The current implementation only accepts a small subset of `AFLPlusPlus` flags for some custom configuration.

## Usage

You can compile it yourself via:

```bash
git clone https://github.com/0xricksanchez/AFL_Runner.git alfrunner
cd aflrunner
cargo build --release
./target/release/afl_runner --help
```

Alternatively you can install via [crates.io](https://crates.io/crates/afl_runner):

```bash
cargo install afl_runner
afl-runner --help
```

## Features

The tools allows for setting the most necessary AFLPlusPlus flags and mimics to some degree the same syntax as AFLplusplus for these things:

- Supported AFLplusplus flags:

  - [x] corpus directory
  - [x] output directory
  - [x] dictionary file
  - [x] Custom `afl-fuzz` binary path for all instances
  - [x] Supply arguments to target binary (including @@)
  - [x] Amount of runner commands to generate

- Other features:
  - [x] Add Tmux option to automatically create an appropriate layout for all runners

## TODO

- [ ] Add remote option.
- [ ] Add more sensible defaults for other options
- [ ] Add more configuration options
- [ ] Allow AFLPlusPlus forks to be used on some amount of runners
