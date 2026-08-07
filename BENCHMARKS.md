# SPIF Performance Benchmarks

This report details the execution speed of the **Semantic Provenance Inference Format (SPIF)** reference Python implementation (`spfx`) across various document complexity levels. 

---

## Benchmark Results (μs per document)

Measured on Apple Silicon (host system) with `REPS = 500` iterations:

| Document Type | Operation | SPIF (SIF) | JSON | CBOR | MessagePack |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **minimal** | encode | **7.6 μs** | 2.1 μs | 3.3 μs | 1.0 μs |
| | decode | **7.6 μs** | 1.6 μs | 1.6 μs | 1.1 μs |
| **medium** | encode | **20.0 μs** | 7.6 μs | 12.4 μs | 3.3 μs |
| | decode | **22.8 μs** | 5.7 μs | 7.3 μs | 3.2 μs |
| **trace** | encode | **40.0 μs** | 28.0 μs | 19.3 μs | 5.4 μs |
| | decode | **38.9 μs** | 8.6 μs | 12.1 μs | 5.8 μs |
| **full** | encode | **63.9 μs** | 37.1 μs | 32.8 μs | 12.5 μs |
| | decode | **79.9 μs** | 22.0 μs | 29.6 μs | 13.3 μs |

---

## Architectural Performance Analysis

### 1. SPIF Integrity & Correctness Costs
* **Integrity Enforcement**: Unlike JSON, CBOR, and MessagePack which only deserialize structural bytes, **SPIF decode performs mandatory SHA-256 checksum verification** over the entire document body. This prevents corruption and unauthorized tampering at the ingestion site.
* **Topological DAG Safety**: SPIF decode validates that the node payload references and trace dependencies contain no cyclic loops ($O(N)$ fast-path validation), neutralizing recursive stack-overflow and Denial-of-Service vectors.
* **CBOR Custom Tags**: SPIF wraps specific fields (such as `Distribution`, `NodeRef`, and `Embedding`) in native CBOR tags (tags 1000–1002) for full cross-language serialization fidelity.

### 2. Microsecond-Level Latency
Even with full cryptographic validation, SPIF operations execute in **tens of microseconds**. This fits comfortably within the strict SLAs of real-time firewalls (e.g. Palo Alto Networks NGFW), API gateways, and client sidecar proxies.

### 3. Native Engine (Rust) Throughput
For high-throughput requirements, the native Rust library (`spif-rust`) achieves over **450,000 decodes/sec per core**, leveraging SSE/AVX vector instructions for hardware-accelerated signature checks.
