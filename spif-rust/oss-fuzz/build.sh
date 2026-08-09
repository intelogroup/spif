#!/bin/bash -eu
cd fuzz-libfuzzer
cargo fuzz build --fuzz-dir . -O
for target in fuzz_read fuzz_read_strict; do
  cp target/x86_64-unknown-linux-gnu/release/$target $OUT/
done
