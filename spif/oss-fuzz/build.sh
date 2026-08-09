#!/bin/bash -eu
pip3 install .

for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  compile_python_fuzzer $fuzzer
done

zip -j $OUT/fuzz_decode_fuzzer_seed_corpus.zip spif/fixtures/cross_lang/*.spif
zip -j $OUT/fuzz_decode_strict_fuzzer_seed_corpus.zip spif/fixtures/cross_lang/*.spif
