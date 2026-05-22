# SPIF — Semantic Provenance Inference Format

Binary file format for AI communication. Encodes LLM outputs with semantic metadata: uncertainty distributions, reasoning traces, provenance, and ed25519 signatures.

## Setup

```bash
pip install -e ".[dev]"
```

Requires Python 3.11+.

## Tests

```bash
pytest tests/
pytest tests/ --cov=spif --cov-report=html
```

Key test files: `test_roundtrip.py`, `test_security.py`, `test_fuzz.py`, `test_edge_cases.py`, `test_hardening.py`.

## Lint

```bash
ruff check spif/ tests/
ruff format spif/ tests/
```

## CLI

After install, the `spif` command is available:

```bash
spif render <path>
spif validate <path>
spif inspect <path> --layer [all|payload|trace|provenance|semantic|alts|signature]
spif hexdump <path>
spif sign <path> --key <mnemonic>
spif verify <path> --signer <url>
```

## Structure

```
spif/         Core package
  types.py   Dataclasses (Distribution, Node, TraceStep, SPIFDocument, …)
  format.py  Binary constants (magic, chunk types, CBOR tags, flags)
  writer.py  SPIFWriter.encode() → bytes
  reader.py  SPIFReader.decode() → SPIFDocument
  renderer.py  Human-readable output
  cli.py     typer CLI app
  crypto.py  ed25519 key ceremony (derive, rotate, revocation)
  exporters/ OpenTelemetry and provenance format adapters
tests/       Roundtrip, security, fuzz, DAG, edge cases (~2400 LOC)
examples/    simple_fact.py, with_uncertainty.py, with_trace.py
benchmarks/  Speed/size comparisons vs JSON/CBOR/MessagePack
compat/      Cross-implementation compat (TypeScript/Deno reader)
tools/       claude_to_spif.py — Claude extended thinking → SPIF
```

## Key conventions

- Roundtrip tests are the primary correctness signal: `write → read → assert equality`
- All binary format constants live in `format.py` — single source of truth
- Validation happens in `__post_init__` on dataclasses (e.g., `Distribution.mean` in [0, 1])
- CBOR encoding uses `canonical=True` for signature-stable serialization
- Custom exception hierarchy: `SPIFError` base, subclasses for magic/version/checksum/signature/format
- `spif/__init__.py` defines the public API surface — add exports there when exposing new types

## Dependencies

- `cbor2` — CBOR binary serialization (RFC 8949)
- `typer` — CLI
- `cryptography` — ed25519 signatures, PBKDF2 key derivation
- `hypothesis` (dev) — property-based fuzz tests
