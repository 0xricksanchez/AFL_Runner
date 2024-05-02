# AFL Runner Example

This example demonstrates how to use `aflr` to start a best-practice multi-core fuzzing campaign for the libxml2 library.
The setup is fully configured via the `Makefile.toml`, whereas the fuzzing campaign behavior is controlled from the `aflr_config.toml`.

## Prerequisites

Before running this example, make sure you have the following dependencies installed:

- Rust programming language (https://www.rust-lang.org/)
- cargo-make (https://github.com/sagiegurari/cargo-make)
- AFL++ (https://github.com/AFLplusplus/AFLplusplus)

## Getting Started

To get started with this example, follow these steps:

1. Clone the repository containing this example.
2. Run the following command from the root directory of this repository:

```shell
$ cargo make
```
