# PQ hybrid benchmark — v1.4 integrated path

Medians of 50 runs, this machine. Spike reference: docs/PQ_SPIKE_VERDICT.md (Phase D).

| Operation | Median (ms) | Spike reference (ms) |
|---|---|---|
| sign hybrid (integrated) | 15.20 | 14.73 (spike prototype) |
| verify hybrid strict — reader gate | 0.55 | 0.53 (spike strict report) |
| verify hybrid strict — trust layer | 0.64 | — |
| verify hybrid classical — reader gate | 0.23 | — |
| sign ed25519 (baseline) | 0.25 | 0.16 (spike) |
| verify ed25519 (baseline) | 0.22 | 0.19 (spike) |

Artifact sizes: unsigned 997 B · ed25519 1087 B · hybrid 7012 B (hybrid − ed25519 = +5925 B; SPEC §7.9.1 records +5,925 B).
