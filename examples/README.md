# AFL++ Fuzzing with AFLR

This example demonstrates how to use `aflr` to start a best-practice multi-core fuzzing campaign for the libxml2 library.
The setup is fully configured via the `Makefile.toml`, whereas the fuzzing campaign behavior is controlled from the `aflr_config.toml`.

## Prerequisites

Make sure you have the following installed before continuing:

- `clang`
- `AFL++`
- `make`
- `autoconf`
- Rust toolchain
- `cargo-make`

## Folder structure

After a successful build of the example, you should see the following files

- `Makefile.toml`: The build configuration file
- `aflr_config.toml`: The `aflr` configuration file (not shown in the example)
- `seed_corpus/`: Directory containing an initial seed corpus
- `xml.dict`: A dictionary/token file
- `libxml2-2.10.0/`: The `libxml2` source code directory
- `xmllint_instr`: The `xmllint` binary with plain AFL++ instrumentation
- `xmllint_san`: The `xmllint` binary with AFL++ instrumentation and sanitizers
- `xmllint_cmplog`: The `xmllint` binary with AFL++ instrumentation and cmplog
- `xmllint_cmpcov`: The `xmllint` binary with AFL++ instrumentation and cmpcov

## Build and run the example

From the root directory of the project simply run:

```bash
cargo make
```

This will fetch all necessary files and kick-start the build-process for all the different `xmllint` binaries.
If the build succeeds `aflr` will based on the `aflr_config.toml` spin up _16_ fuzzing processes that closely follow
the recommended best-practice setup described [here](https://aflplus.plus/docs/fuzzing_in_depth/#c-using-multiple-cores)

_Note_: You can also just run `cargo make run_dry` to simply run the command generator (requires building) instead of running the actual fuzzing!
