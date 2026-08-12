#!/bin/bash -eu
pip3 install .
# pip3 install has silently no-op'd here before (wrong WORKDIR, no
# pyproject.toml in cwd) without the build failing loudly. Confirm the
# INSTALLED package is importable before compiling fuzzers against it — run
# from a directory with no local spif/ subdir, since cwd is on sys.path and
# would otherwise shadow a broken/absent install with the source checkout.
(cd /tmp && python3 -c "import spif") || { echo "FATAL: spif not importable after pip3 install ." >&2; exit 1; }

while IFS= read -r -d '' fuzzer; do
  compile_python_fuzzer "$fuzzer"
done < <(find "$SRC" -type f -name '*_fuzzer.py' -print0)

zip -j "$OUT/fuzz_decode_fuzzer_seed_corpus.zip" "$SRC/spif/spif/fixtures/cross_lang/"*.spif
zip -j "$OUT/fuzz_decode_strict_fuzzer_seed_corpus.zip" "$SRC/spif/spif/fixtures/cross_lang/"*.spif

# The frozen fuzzer binaries package their own copy of `spif` at compile
# time — a working pip install doesn't guarantee pyinstaller actually
# bundled it. Smoke-test each compiled fuzzer against one real input before
# declaring the build done, so a broken binary fails CI here instead of
# silently fuzzing nothing for 300s.
smoketest_log=$(mktemp)
trap 'rm -f "$smoketest_log"' EXIT

for pkg in "$OUT"/*_fuzzer.pkg; do
  chmod +x "$pkg"
  seed=$(find "$SRC/spif/spif/fixtures/cross_lang" -name '*.spif' | head -n1)
  if ! "$pkg" -runs=1 "$seed" >"$smoketest_log" 2>&1; then
    echo "FATAL: $pkg failed to run against a real seed input:" >&2
    cat "$smoketest_log" >&2
    exit 1
  fi
  chmod -x "$pkg"
done
