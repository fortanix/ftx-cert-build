#!/usr/bin/env bash

set -xe

# Run builds and run all tests
cargo fmt --check --all --verbose
cargo build --lib
cargo build --examples
cargo test --all-features
cargo clippy --workspace --all-targets --all-features -- --no-deps -D warnings
