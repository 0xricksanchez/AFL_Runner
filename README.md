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

- [ ] Add LAF-Intel/CMPCOV option
- [ ] Add remote option.
- [ ] Add more sensible defaults for other options
- [ ] Add more configuration options
- [ ] Allow AFLPlusPlus forks to be used on some amount of runners

## Showcase

If you generate your AFL++ commands it may look similar to the following below.

```bash
afl_runner -t test_bins/target -s test_bins/target_asan -c test_bins/target_cmplog -n 8 -i /tmp/seed_corpus -o /tmp/afl_out -x /tmp/fuzzing.dict -m "custom_fuzz_session" --dry-run -- 'arg1 arg2 --arg3 --arg4 @@'
Generated commands:
    0. AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=1 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250  /usr/local/bin/afl-fuzz -Z -p fast -i /tmp/seed_corpus -o /tmp/afl_out -M main_target -x /tmp/fuzzing.dict -- /home/fuzz_serv/git/priv/afl_runner/test_bins/target_asan arg1 arg2 --arg3 --arg4 @@
    1. AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=0 AFL_EXPAND_HAVOC_NOW=1 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250  /usr/local/bin/afl-fuzz -P explore -p explore -i /tmp/seed_corpus -o /tmp/afl_out -S slave_0_target -x /tmp/fuzzing.dict -l 2 -c /home/fuzz_serv/git/priv/afl_runner/test_bins/target_cmplog -- /home/fuzz_serv/git/priv/afl_runner/test_bins/target arg1 arg2 --arg3 --arg4 @@
    2. AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=0 AFL_KEEP_TIMEOUTS=1 AFL_EXPAND_HAVOC_NOW=1 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250  /usr/local/bin/afl-fuzz -a text -p coe -i /tmp/seed_corpus -o /tmp/afl_out -S slave_1_target -x /tmp/fuzzing.dict -l 2AT -c /home/fuzz_serv/git/priv/afl_runner/test_bins/target_cmplog -- /home/fuzz_serv/git/priv/afl_runner/test_bins/target arg1 arg2 --arg3 --arg4 @@
    3. AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=1 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250  /usr/local/bin/afl-fuzz -P explore -p lin -i /tmp/seed_corpus -o /tmp/afl_out -S slave_2_target -x /tmp/fuzzing.dict -- /home/fuzz_serv/git/priv/afl_runner/test_bins/target arg1 arg2 --arg3 --arg4 @@
    4. AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=0 AFL_KEEP_TIMEOUTS=0 AFL_EXPAND_HAVOC_NOW=1 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250  /usr/local/bin/afl-fuzz -P exploit -a binary -p quad -i /tmp/seed_corpus -o /tmp/afl_out -S slave_3_target -x /tmp/fuzzing.dict -- /home/fuzz_serv/git/priv/afl_runner/test_bins/target arg1 arg2 --arg3 --arg4 @@
    5. AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=0 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250  /usr/local/bin/afl-fuzz -a binary -p exploit -i /tmp/seed_corpus -o /tmp/afl_out -S slave_4_target -x /tmp/fuzzing.dict -- /home/fuzz_serv/git/priv/afl_runner/test_bins/target arg1 arg2 --arg3 --arg4 @@
    6. AFL_AUTORESUME=1 AFL_FINAL_SYNC=0 AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=0 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250  /usr/local/bin/afl-fuzz -P explore -p rare -i /tmp/seed_corpus -o /tmp/afl_out -S slave_5_target -x /tmp/fuzzing.dict -- /home/fuzz_serv/git/priv/afl_runner/test_bins/target arg1 arg2 --arg3 --arg4 @@
    7. AFL_AUTORESUME=1 AFL_FINAL_SYNC=1 AFL_DISABLE_TRIM=0 AFL_KEEP_TIMEOUTS=1 AFL_EXPAND_HAVOC_NOW=0 AFL_IGNORE_SEED_PROBLEMS=0 AFL_IMPORT_FIRST=0 AFL_TESTCACHE_SIZE=250  /usr/local/bin/afl-fuzz -a text -p fast -i /tmp/seed_corpus -o /tmp/afl_out -S slave_6_target -x /tmp/fuzzing.dict -- /home/fuzz_serv/git/priv/afl_runner/test_bins/target arg1 arg2 --arg3 --arg4 @@
```

_Note_: Supplying the sanitizer, CMPLOG, or CMPCOV binaries are optional and if omitted all invocations just contain the instrumented target instead.
