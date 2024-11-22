#!/usr/bin/env sh

cargo clippy -- -W clippy::all -W clippy::pedantic -W clippy::nursery -D warnings --no-deps -A clippy::missing_const_for_fn -A clippy::must_use_candidate
