#!/usr/bin/env bash

set -xe

# Run builds and run all tests
cargo fmt --check --all --verbose
cargo build --lib
cargo build --examples

# Check build when individual crypto features are disabled
algorithms=("" "rsa" "ecdsaecdh")

for algorithm in "${algorithms[@]}"; do
   cargo check --no-default-features --features "$algorithm"
done

cargo test --all-features
cargo clippy --workspace --all-targets --all-features -- --no-deps -D warnings
