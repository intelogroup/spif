#!/bin/bash -eu
pip3 install .

while IFS= read -r -d '' fuzzer; do
  compile_python_fuzzer "$fuzzer"
done < <(find "$SRC" -type f -name '*_fuzzer.py' -print0)

zip -j "$OUT/fuzz_decode_fuzzer_seed_corpus.zip" "$SRC/spif/spif/fixtures/cross_lang/"*.spif
zip -j "$OUT/fuzz_decode_strict_fuzzer_seed_corpus.zip" "$SRC/spif/spif/fixtures/cross_lang/"*.spif
