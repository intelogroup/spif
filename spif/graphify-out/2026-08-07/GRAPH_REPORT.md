# Graph Report - spfx  (2026-08-06)

## Corpus Check
- 152 files · ~133,315 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 2740 nodes · 7840 edges · 139 communities (135 shown, 4 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 793 edges (avg confidence: 0.53)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `14e2876c`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- SPIFDocument
- SemanticLayer
- test_model_comprehension.py
- SPIFDocument
- reader.py
- streaming.py
- wrap_text
- index.ts
- sif_reader.ts
- Node
- Provenance
- live_failure_telemetry_bench.py
- tamper_detection_compare.py
- gemini_adapter.py
- SPIFKeyStore
- reader.ts
- OpenAISPIFAdapter
- Signature
- synthetic_generators.py
- to_otel_span
- Distribution
- full_bench.py
- AnthropicSPIFAdapter
- SPIFDocument
- openai_adapter.py
- SPIFReader
- bench_realworld.py
- otel_vs_spif_bench.py
- GeminiSPIFAdapter
- live_api_bench.py
- SPIFStreamWriter
- test_tool_adapters.py
- audit_chain_bench.py
- openai.ts
- test_keystore.py
- Alternative
- _doc_full
- iter_events
- ai_native_bench.py
- cli.py
- SPIFRenderer
- compilerOptions
- SPIF v1.0.0 — Semantic Provenance Inference Format
- anthropic_adapter.py
- test_gemini_adapter.py
- test_hardening_scenarios.py
- test_elite_challenges.py
- generate_compat_fixtures.py
- format_comparator.py
- calibration_bench.py
- test_hardening.py
- bench_size.py
- cbor-utils.ts
- compat.test.ts
- test_real_world_acceptance.py
- adversarial_resistance_bench.py
- .decode
- _make_key
- test_signature.py
- langchain_adapter.py
- llm_judge_runner.py
- SPIF — Semantic Provenance Inference Format
- test_live_provider_acceptance.py
- _parse_resume_token
- test_task_chunk.py
- Enterprise Readiness — Making Top AI Companies Try SPIF
- doc_full
- hard_sif_bench.py
- compute_content_id
- test_fuzz.py
- .test_strip_sig_chunk_verify_returns_false
- test_rust_sidecar.py
- _minimal_doc
- eu_ai_act_audit.py
- hard_bench.py
- claude_to_sif.py
- package.json
- _write_spif
- run_full_comparison
- SPIFStreamWriter
- SPIFStreamReader
- SPIFWriter
- TestKeyManagement
- Format Comparison
- Key Findings
- Quickstart
- 6. Chunk Payload Schemas
- test_c2pa_watermark_edge.py
- _key_slug
- mlflow_adapter.py
- adversarial_stress_test.py
- calibration_study.py
- resumability_study.py
- tamper_demo.py
- devDependencies
- keywords
- agent_chain_e2e.py
- _make_demo_file
- mmlu_bench.py
- jest
- _make_doc
- test_tamper_latency.py
- bench_speed_percentiles.py
- SPIF — Semantic Provenance Inference Format
- Detailed Findings
- SPIF — Semantic Provenance Inference Format
- SPIF v0.2.0 (proposed)
- 5. Data Types
- test_cross_language_cbor.py
- SPIF Cryptographic Implementation Audit
- SidecarHTTPHandler
- bench_token_cost.py
- TestChecksumCompleteness
- 10. Streaming Protocol (SSPIF)
- .test_checksum_chunk_body_replacement_detected
- _sign_doc
- ._inject_and_decode
- pytest_collection_modifyitems
- Quickstart
- 12. Conformance
- 7. Integrity and Authentication
- otel.py
- .test_checksum_tamper_raises_not_asserts
- scripts
- 2. File Layout
- dependencies
- test_compat.sh
- files
- repository
- SPIF Project Roadmap Update
- 4. CBOR Encoding
- spfx
- prov.py
- TestRoundTripLoss

## God Nodes (most connected - your core abstractions)
1. `SPIFReader` - 312 edges
2. `Node` - 288 edges
3. `SPIFWriter` - 271 edges
4. `Distribution` - 244 edges
5. `SPIFDocument` - 237 edges
6. `Provenance` - 189 edges
7. `TraceStep` - 140 edges
8. `Signature` - 129 edges
9. `NodeRef` - 91 edges
10. `SPIFStreamWriter` - 90 edges

## Surprising Connections (you probably didn't know these)
- `FormatStats` --uses--> `Distribution`  [INFERRED]
  benchmarks/adversarial_resistance_bench.py → spfx/types.py
- `FormatStats` --uses--> `Provenance`  [INFERRED]
  benchmarks/adversarial_resistance_bench.py → spfx/types.py
- `FormatStats` --uses--> `TraceStep`  [INFERRED]
  benchmarks/adversarial_resistance_bench.py → spfx/types.py
- `BenchResult` --uses--> `Distribution`  [INFERRED]
  benchmarks/adversarial_resistance_bench.py → spfx/types.py
- `BenchResult` --uses--> `Provenance`  [INFERRED]
  benchmarks/adversarial_resistance_bench.py → spfx/types.py

## Import Cycles
- None detected.

## Communities (139 total, 4 thin omitted)

### Community 0 - "SPIFDocument"
Cohesion: 0.06
Nodes (36): _d(), _encode_decode(), _n(), _prov(), Distribution, Node, Provenance, skipif (+28 more)

### Community 1 - "SemanticLayer"
Cohesion: 0.06
Nodes (30): Dense vector representation of the document's meaning., SemanticLayer, _node(), SPIFDocument, Comprehensive edge case tests for SIF format. Covers boundary conditions, field…, s0 → s1, s0 → s2, s1+s2 → s3 (two paths converging)., 10 independent roots, 1 sink., 1536-dimension embedding (OpenAI ada-002 size). (+22 more)

### Community 2 - "test_model_comprehension.py"
Cohesion: 0.12
Nodes (27): Exception, SPIFDocument, Raised when a document's (signer, nonce) pair has already been seen., Raise SPIFReplayError if this document's signer+nonce was already seen., SPIFReplayError, _ask(), _json_manual(), _make_doc_safe() (+19 more)

### Community 3 - "SPIFDocument"
Cohesion: 0.08
Nodes (25): _dist(), _encode_decode(), _node(), _prov(), Distribution, parametrize, Provenance, slow (+17 more)

### Community 4 - "reader.py"
Cohesion: 0.06
Nodes (44): check_revocation(), export_pem_private_key(), export_pem_public_key(), generate_key(), load_pem_private_key(), load_revocation_list(), Ed25519PrivateKey, Path (+36 more)

### Community 5 - "streaming.py"
Cohesion: 0.12
Nodes (25): NodeRef, SPIFDocument, SPIF Streaming (SSPIF) — incremental delivery protocol. Wire format (strict…, Finalize the stream. Emits PAYLOAD (and TRACE/ALTS/DELTA/SIG chunks if…, _cbor(), _cbor_fast(), _chunk(), _compress_bytes() (+17 more)

### Community 6 - "wrap_text"
Cohesion: 0.14
Nodes (11): _anthropic_response(), _anthropic_thinking_response(), _make_mock_client(), SimpleNamespace, TestCallClaude, TestWrapText, tool, call_claude() (+3 more)

### Community 7 - "index.ts"
Cohesion: 0.11
Nodes (47): CHUNK_ALTS, CHUNK_CHECKSUM, CHUNK_DELTA, CHUNK_HEADER, CHUNK_MULTISIG, CHUNK_NAMES, CHUNK_PARTIAL_TEXT, CHUNK_PAYLOAD (+39 more)

### Community 8 - "sif_reader.ts"
Cohesion: 0.06
Nodes (42): CBORDecoder, CHUNK_NAMES, decodeCBOR(), Distribution, inflateZlib(), MAGIC, main(), NodeRef (+34 more)

### Community 9 - "Node"
Cohesion: 0.14
Nodes (36): Node, A content node in the payload graph., SPIFDocument, Roundtrip tests: write then read, assert equality across all layer combinations., Full document with every optional layer present., Response node can ref the tool result it consumed., SPIFWriter(compress=True) → SPIFReader().decode() gives same result., Uncompressed docs still read fine after adding compression support. (+28 more)

### Community 10 - "Provenance"
Cohesion: 0.09
Nodes (31): CRLClient, generate_fpr_document(), PolicyEvaluator, _provenance_to_dict(), Path, Provenance, SPIFDocument, SPIF Sidecar Proxy & Verification Server. Provides runtime policy enforcement,… (+23 more)

### Community 11 - "live_failure_telemetry_bench.py"
Cohesion: 0.10
Nodes (40): analyze_result(), build_otel_json(), build_spif_from_tool_interaction(), execute_tool(), _infer_system(), _input_hash(), main(), _pack() (+32 more)

### Community 12 - "tamper_detection_compare.py"
Cohesion: 0.10
Nodes (31): _b64url(), _b64url_decode(), _flip_bit(), _FormatResult, _gpg_available(), _GPGSigner, _HMACSigner, _inject_value() (+23 more)

### Community 13 - "gemini_adapter.py"
Cohesion: 0.09
Nodes (26): _build_doc(), _build_provenance(), _confidence_from_logprobs(), _extract_chunk_content(), _input_hash(), _make_legacy_generation_config(), _messages_to_contents(), _messages_to_prompt() (+18 more)

### Community 14 - "SPIFKeyStore"
Cohesion: 0.12
Nodes (14): Path, SPIFDocument, Return True if a public key for key_id is registered., Return a list of registered key IDs (unslugged names not preserved)., Mark a key as revoked. Revoked keys will be rejected during verification even…, Remove a key from the revocation list. Returns True if it was revoked., Return True if key_id appears in the revocation list., Return a mapping of {key_id: revoked_at_ms} for all revoked keys. (+6 more)

### Community 15 - "reader.ts"
Cohesion: 0.10
Nodes (19): SPIFChecksumError, SPIFError, SPIFFormatError, SPIFMagicError, SPIFSignatureError, SPIFVersionError, MAGIC, Chunk (+11 more)

### Community 16 - "OpenAISPIFAdapter"
Cohesion: 0.12
Nodes (21): OpenAISPIFAdapter, Wraps an OpenAI client and produces SPIF bytes or SPIFDocuments. Parameters…, _chunk(), _lp(), _make_client(), _make_complete_response(), _make_stream(), Any (+13 more)

### Community 17 - "Signature"
Cohesion: 0.22
Nodes (29): SPIFChecksumError, SPIFFormatError, SPIFMagicError, Delta, NodeRef, Express this document as a diff from a base state., ed25519 signature over the document body (v0.2+)., A typed reference to another node by ID. (+21 more)

### Community 18 - "synthetic_generators.py"
Cohesion: 0.11
Nodes (32): _dist(), gen_adversarial(), gen_complex_trace(), gen_extreme_dist(), gen_full(), gen_large_embeddings(), gen_max_payload(), gen_medium() (+24 more)

### Community 19 - "to_otel_span"
Cohesion: 0.11
Nodes (14): SPIFDocument, Convert a SPIFDocument to an OTel GenAI span dict. Returns a dict that matches…, to_otel_span(), _doc_with_tool_success(), SPIFDocument, Tests for SIF exporters (OTel, PROV-JSON)., Bug 1 fix: status must be ERROR when any tool_result has is_error=True., Bug 2 fix: NODE_TOOL_CALL nodes must produce gen_ai.tool.call events. (+6 more)

### Community 20 - "Distribution"
Cohesion: 0.07
Nodes (36): json_equivalent(), SPIFDocument, A3 — Expressiveness comparison: what SIF expresses that JSON cannot enforce.…, Best-effort JSON. Shows what gets lost: - Distribution becomes 3 fields with no…, run(), sif_document(), Example: SIF document with full reasoning trace DAG., create_target_doc() (+28 more)

### Community 21 - "full_bench.py"
Cohesion: 0.08
Nodes (18): Best-effort JSON encoding using naming conventions., to_json_dict(), bench_fn(), dec_sif(), enc_arrow(), enc_bson(), enc_cbor(), enc_json() (+10 more)

### Community 22 - "AnthropicSPIFAdapter"
Cohesion: 0.14
Nodes (20): AnthropicSPIFAdapter, Wraps an Anthropic client and produces SIF bytes or SPIFDocuments. Parameters…, _imports(), skipif, slow, Live integration tests — require a real ANTHROPIC_API_KEY in the environment.…, test_chained_calls_link_via_context_ref(), test_complete_returns_valid_document() (+12 more)

### Community 23 - "SPIFDocument"
Cohesion: 0.12
Nodes (27): main(), Test 7 — Replay protection + EU AI Act compliance fields. Pass: (a) re-…, ReplayGuard, A complete SPIF document., Derived status: 'failed' if any tool_result node has is_error=True, else 'ok'., SHA-256 of the canonical CBOR encoding of {payload, trace, provenance}. Use as…, SPIFDocument, _payload() (+19 more)

### Community 24 - "openai_adapter.py"
Cohesion: 0.14
Nodes (18): _build_doc(), _build_provenance(), _confidence_from_logprobs(), _execute_tools_oai(), _input_hash(), _normalise_messages(), Any, Distribution (+10 more)

### Community 25 - "SPIFReader"
Cohesion: 0.12
Nodes (19): Deserializes SPIF documents from bytes or files. Parameters ----------…, Return a reader that rejects unsigned documents. Equivalent to…, SPIFReader, _encoded(), _minimal_doc(), test_bad_magic_raises(), test_empty_payload_raises_format_error(), test_missing_payload_raises() (+11 more)

### Community 26 - "bench_realworld.py"
Cohesion: 0.18
Nodes (29): bandwidth_mb(), bench_compression(), bench_fn(), bench_memory(), bench_pipeline_simulation(), bench_signature_overhead(), bench_streaming_latency(), bench_streaming_throughput() (+21 more)

### Community 27 - "otel_vs_spif_bench.py"
Cohesion: 0.16
Nodes (28): bench(), flip_byte(), _prov(), SPIFDocument, SPIF vs JSON+OTel — AI Failure Telemetry Benchmark…, Full: multi-tool agent task that aborts after 3 failed tool calls., Simulate the JSON+OTel stack: SPIF → OTel span → JSON bytes., OTel span encoded as CBOR (e.g. as sent over OTLP binary). (+20 more)

### Community 28 - "GeminiSPIFAdapter"
Cohesion: 0.16
Nodes (14): GeminiSPIFAdapter, Wraps a Gemini model client and produces SPIF bytes or SPIFDocuments.…, _make_genai_client(), _make_legacy_client(), _make_simple_chunk(), _make_thinking_chunk(), Minimal chunk with a single text part., Chunk with both a thinking part and a text part. (+6 more)

### Community 29 - "live_api_bench.py"
Cohesion: 0.14
Nodes (15): AnthropicBench, _available_providers(), main(), _make_provider(), _mean(), OpenAIBench, _print_optional_summary(), _print_summary() (+7 more)

### Community 30 - "SPIFStreamWriter"
Cohesion: 0.07
Nodes (19): Provenance, Produces a streaming SPIF byte sequence piece by piece. All methods return…, Return a resume token encoding the current position in the stream. The token is…, Emit the stream header (magic, version, flags, HEADER chunk, optional…, Emit a PARTIAL_TEXT chunk for one text fragment (e.g., one LLM token). May be…, Return all bytes emitted so far (for testing or saving to file). Only valid…, SPIFStreamWriter, commit() with no partial_text() calls must produce valid SIF. (+11 more)

### Community 31 - "test_tool_adapters.py"
Cohesion: 0.15
Nodes (14): _FakeChoice, _FakeFunction, _FakeLogprobs, _FakeOAIChat, _FakeOAIClient, _FakeOAICompletions, _FakeOAIMessage, _FakeOAIResponse (+6 more)

### Community 32 - "audit_chain_bench.py"
Cohesion: 0.15
Nodes (24): _build_flat_array(), _build_json_hash_chain(), _build_manifest_chain(), _build_spif_chain(), ChainResult, _hop_to_json_dict(), _make_hop(), _mean_us() (+16 more)

### Community 33 - "openai.ts"
Cohesion: 0.13
Nodes (14): buildNode(), buildProvenance(), concat(), logprobsToDistribution(), Message, normalizePrompt(), OpenAIAdapterOptions, OpenAISPIFAdapter (+6 more)

### Community 34 - "test_keystore.py"
Cohesion: 0.13
Nodes (14): derive_key_from_mnemonic(), Derive a deterministic ed25519 private key from a BIP39-style mnemonic phrase.…, alice_key(), bob_key(), fixture, Tests for SPIFKeyStore — file-based public key management and verification., tmp_ks(), Same mnemonic always produces the same ed25519 key. (+6 more)

### Community 35 - "Alternative"
Cohesion: 0.19
Nodes (20): _body(), _decode_value(), _dist(), _encode_value(), from_msgpack(), Any, Distribution, SPIFDocument (+12 more)

### Community 36 - "_doc_full"
Cohesion: 0.20
Nodes (9): SPIFDocument, Convert a SPIFDocument to a W3C PROV-JSON dict. Returns a dict suitable for…, to_prov(), _doc_full(), Distribution is stored as plain attributes — type enforcement lost., SHA-256 checksum has no PROV equivalent — verify it's absent., Signer identity is preserved as prov:Agent, but crypto bytes are dropped., After PROV export, DAG edges lose their type information. (+1 more)

### Community 37 - "iter_events"
Cohesion: 0.11
Nodes (21): iter_events(), Yield StreamEvents from a complete (possibly streaming) SPIF byte sequence.…, _minimal_doc(), _minimal_node(), _prov(), Node, Provenance, SPIFDocument (+13 more)

### Community 38 - "ai_native_bench.py"
Cohesion: 0.20
Nodes (21): approx_tokens(), bench(), gzip_size(), make_cbor_doc(), make_json_doc(), make_jsonl_doc(), make_msgpack_doc(), make_spif_doc() (+13 more)

### Community 39 - "cli.py"
Cohesion: 0.11
Nodes (28): command, export(), hexdump(), inspect(), Path, SPIF command-line interface., Show the raw chunk structure of a SPIF file., Sign a SPIF file with an ed25519 private key. (+20 more)

### Community 40 - "SPIFRenderer"
Cohesion: 0.15
Nodes (21): bench(), make_json_doc(), make_msgpack_doc(), make_spif_doc(), make_xml_doc(), make_yaml_doc(), SPIFDocument, Readability Benchmark — Scenarios A & B… (+13 more)

### Community 41 - "compilerOptions"
Cohesion: 0.09
Nodes (22): compilerOptions, declaration, declarationMap, esModuleInterop, forceConsistentCasingInFileNames, lib, module, moduleResolution (+14 more)

### Community 42 - "SPIF v1.0.0 — Semantic Provenance Inference Format"
Cohesion: 0.09
Nodes (22): Acknowledgments, Backward Compatibility, Breaking Changes from Previous Releases, For Consumers (Reading SPIF Documents), For Infrastructure (Audit & Observability), For Producers (Creating SPIF Documents), Future Direction (v1.1 and Beyond), Guidance for Users (+14 more)

### Community 43 - "anthropic_adapter.py"
Cohesion: 0.13
Nodes (21): _build_doc(), _build_provenance(), _build_tool_call_node(), _execute_tools(), _input_hash(), _normalise_messages(), Any, Distribution (+13 more)

### Community 44 - "test_gemini_adapter.py"
Cohesion: 0.20
Nodes (13): _lp_entry(), _make_chunk(), _make_complete_response(), _make_logprob_chunk(), _make_part(), Any, SimpleNamespace, Tests for GeminiSPIFAdapter. All tests run offline — no API key required. The… (+5 more)

### Community 45 - "test_hardening_scenarios.py"
Cohesion: 0.16
Nodes (22): _find_chunk_offset_unchecked(), _make_key(), Ed25519PrivateKey, SPIFDocument, Dedicated unit tests for advanced security hardening scenarios, including: 1.…, Verify time-bounded signature checks under extreme clock drift/skew conditions., Verify that deep nested CBOR objects inside chunks do not crash the parser…, Verify that spoofing signer IDs inside the document causes keystore validation… (+14 more)

### Community 46 - "test_elite_challenges.py"
Cohesion: 0.14
Nodes (20): Signature, _find_first_auth_chunk_offset(), Return the byte offset of the first SIGNATURE or MULTISIG chunk. The signing…, _generate_key_pair(), Ed25519PrivateKey, SPIFDocument, Elite Category Challenges for SPIF (Semantic Provenance Inference Format).…, Simulates an RFC 3161 compliant Time-Stamping Authority (TSA). (+12 more)

### Community 47 - "generate_compat_fixtures.py"
Cohesion: 0.20
Nodes (19): _append_unknown_chunk(), _auth_offset(), _dist(), generate_fixtures(), main(), _manifest_entry(), _multisign_doc(), _provenance() (+11 more)

### Community 48 - "format_comparator.py"
Cohesion: 0.13
Nodes (14): dec_sif(), enc_bson(), enc_cbor(), enc_json(), enc_json_minimal(), enc_msgpack(), enc_sif(), print_report() (+6 more)

### Community 49 - "calibration_bench.py"
Cohesion: 0.18
Nodes (18): ask_with_confidence(), check_correct(), compute_ece(), _fuzzy_match(), load_simpleqa(), load_truthfulqa(), main(), Anthropic (+10 more)

### Community 50 - "test_hardening.py"
Cohesion: 0.16
Nodes (18): _make_key(), SPIFDocument, Dedicated unit tests for SPIF security hardening and production gotchas., Test that verify_signature method respects max_signature_age_seconds parameter., Rejects signature age check if provenance is missing but age limit is active., Verify that OpenAISPIFAdapter captures response.model snapshot inside…, Verify fallback to requested model if response.model is empty or None., Verify that derive_key_from_mnemonic warns when passphrase is empty or None. (+10 more)

### Community 51 - "bench_size.py"
Cohesion: 0.18
Nodes (14): A2 — Size benchmark: SIF vs JSON vs CBOR vs MessagePack vs Protobuf. Generates…, Raw CBOR without SIF framing — baseline for overhead measurement., run(), to_cbor_raw(), to_msgpack_raw(), to_proto_raw(), bench(), A2 — Speed benchmark: encode/decode throughput. Measures encode + decode time… (+6 more)

### Community 52 - "cbor-utils.ts"
Cohesion: 0.20
Nodes (16): cborEncode(), decodeDistributionFromRaw(), decodeNodeFromRaw(), decodeStepFromRaw(), encodeDistribution(), encodeEmbedding(), encodeNode(), encodeNodeRef() (+8 more)

### Community 53 - "compat.test.ts"
Cohesion: 0.15
Nodes (9): cborDecode(), cborLoad(), SPIFStreamReader, findPythonWithSpifDeps(), generateFixtures(), Manifest, ManifestEntry, readHeaderFlags2() (+1 more)

### Community 54 - "test_real_world_acceptance.py"
Cohesion: 0.27
Nodes (15): _agent_doc(), _baseline_doc(), _dist(), _find_auth_offset(), _find_chunk_offset(), _pub_b64(), Distribution, Ed25519PrivateKey (+7 more)

### Community 55 - "adversarial_resistance_bench.py"
Cohesion: 0.14
Nodes (23): BenchResult, FormatStats, _inject_unknown_chunk(), _mutate(), _mutate_chunk_length_overflow(), _mutate_magic_byte(), _print_results(), _print_structural() (+15 more)

### Community 56 - ".decode"
Cohesion: 0.10
Nodes (20): _cbor_load(), _decode_node(), _decode_step(), _iter_chunks(), CBORTag, Node, Path, SPIFDocument (+12 more)

### Community 57 - "_make_key"
Cohesion: 0.16
Nodes (13): _find_chunk_offset(), _make_key(), _multisign_doc(), SPIFDocument, Return byte offset of first occurrence of chunk_type (or None)., Multi-sig document survives encode → decode with all signatures preserved., All-valid multi-sig: verify_signature returns True., If one signature in CHUNK_MULTISIG is wrong, verify raises SPIFSignatureError. (+5 more)

### Community 58 - "test_signature.py"
Cohesion: 0.26
Nodes (16): _make_key(), SPIFDocument, ed25519 signature: roundtrip, tamper detection, verification., Attack 3 regression: tamper payload + recompute checksum, keep stale sig bytes.…, The CHECKSUM must cover the SIGNATURE chunk bytes., Two-pass signing: 1. Encode with a dummy 64-byte signature to lock in the final…, verify_signature raises SPIFSignatureError when signer field holds wrong public…, _sign_doc() (+8 more)

### Community 59 - "langchain_adapter.py"
Cohesion: 0.17
Nodes (12): AIMessage, BaseChatModel, BaseMessage, demo_drop_in(), demo_manual_wrap(), Any, SPIFDocument, LangChain + SPIF — wrap any LangChain LLM call with tamper-evident provenance.… (+4 more)

### Community 60 - "llm_judge_runner.py"
Cohesion: 0.17
Nodes (15): build_judge_prompt(), judge_single_document(), parse_judge_response(), print_judge_report(), Path, LLM Judge Runner: Run existing llm_judge.py on generated SIF files and…, Parse Claude's structured response into per-criterion dicts., Judge a single SIF document. (+7 more)

### Community 61 - "SPIF — Semantic Provenance Inference Format"
Cohesion: 0.12
Nodes (16): 11. Version Negotiation, 13. MIME Type and File Association, 14.1 Test Vectors, 14. Reference Implementations, 1. Purpose, 3.1 Chunk Type Registry, 3.2 Required Chunk Order, 3. Chunk Framing (+8 more)

### Community 62 - "test_live_provider_acceptance.py"
Cohesion: 0.33
Nodes (11): _assert_exportable_and_signable(), _consume_stream(), _find_auth_offset(), _pub_b64(), Ed25519PrivateKey, skipif, Live provider acceptance tests for real API keys. These tests are broader than…, _sign_bytes() (+3 more)

### Community 63 - "_parse_resume_token"
Cohesion: 0.19
Nodes (8): _make_resume_token(), _parse_resume_token(), Encode seq + body_hash as a base64url resume token., Decode a resume token back to (seq, body_hash). Raises ValueError if the token…, Unit tests for resume token encode/decode., Token must not contain + or / (urlsafe base64)., The 'resumed' event must carry a valid resume_token string., TestResumeToken

### Community 64 - "test_task_chunk.py"
Cohesion: 0.22
Nodes (9): _minimal_doc(), SPIFDocument, Tests for CHUNK_TASK roundtrip, flags2 bit, and optional presence., Documents without TaskInfo still roundtrip correctly., FLAG_HAS_TASK bit must be set in serialized bytes when task_info is present., No CHUNK_TASK byte in output when task_info is None., TaskInfo present alongside all other optional layers., TestTaskChunkRoundtrip (+1 more)

### Community 65 - "Enterprise Readiness — Making Top AI Companies Try SPIF"
Cohesion: 0.12
Nodes (15): 10. Benchmarks in the Repo, 1. Zero-Friction First Experience, 2. One-Line Integration into Their Stack, 3. Rich Type Hints & IDE Support, 4. Async Everywhere, 5. Rich Error Messages, 6. Deterministic, Reproducible Output, 7. Minimal Dependency Tree (+7 more)

### Community 66 - "doc_full"
Cohesion: 0.19
Nodes (15): _make_corpus(), SPIFDocument, Produce n documents evenly spread across complexity levels., _dist(), doc_full(), doc_medium(), doc_minimal(), doc_with_trace() (+7 more)

### Community 67 - "hard_sif_bench.py"
Cohesion: 0.19
Nodes (14): ensure_directories(), generate_markdown_report(), main(), SIF Hard Benchmark - Main Orchestrator Runs the complete hard benchmark: 1.…, Run format comparison benchmark., Run LLM judge on generated files., Generate comprehensive markdown report., Create output directories. (+6 more)

### Community 68 - "compute_content_id"
Cohesion: 0.08
Nodes (23): ConsumerCorp, ProviderCorp, Ed25519PrivateKey, SPIFDocument, Cross-organization AI output handoff — trust without a shared intermediary.…, run(), _sign(), _status() (+15 more)

### Community 69 - "test_fuzz.py"
Cohesion: 0.19
Nodes (14): given, settings, _minimal_sif(), A1 — Fuzz + property-based tests. Claims tested: 1. SPIFReader never raises…, Reader must only raise SPIFError (or subclass) on any input, never crash., Valid magic + version + flags but random body → only SPIFError., Flipping any bit in the body raises SPIFChecksumError., Truncating at any byte in [1, len-1] raises SPIFError, never crashes. (+6 more)

### Community 70 - ".test_strip_sig_chunk_verify_returns_false"
Cohesion: 0.20
Nodes (9): _find_chunk_offset_unchecked(), Replace the CBOR payload of chunk_type with new_cbor, recompute the checksum,…, Like _find_chunk_offset but also finds CHUNK_CHECKSUM., Remove CHUNK_SIGNATURE from a signed document, recompute checksum.…, Unsigning a document from the start returns False, not raises., Return body + fresh CHECKSUM chunk., _recompute_checksum(), _replace_chunk_data() (+1 more)

### Community 71 - "test_rust_sidecar.py"
Cohesion: 0.20
Nodes (12): compile_rust_sidecar(), get_free_port(), keys(), MockCRLHandler, MockUpstreamHandler, policy_file(), BaseHTTPRequestHandler, fixture (+4 more)

### Community 72 - "_minimal_doc"
Cohesion: 0.20
Nodes (7): _minimal_doc(), Same payload, different provenance.timestamp_ms → different checksums. The…, Any change to payload changes the checksum., Truncating the document at any point must raise a SPIFError subclass, never a…, compute_content_id changes when payload content changes., TestReplayAttack, TestTruncation

### Community 73 - "eu_ai_act_audit.py"
Cohesion: 0.24
Nodes (13): audit_artifact(), generate_decision(), Ed25519PrivateKey, Path, SPIFDocument, EU AI Act Article 12 — tamper-evident AI output logging with SPIF. Art. 12…, Inflate confidence mean from 0.87 → 0.99 in raw CBOR bytes (post-hoc fraud)., Simulate a high-risk AI system producing a clinical risk score. (+5 more)

### Community 74 - "hard_bench.py"
Cohesion: 0.23
Nodes (13): ask_hard_question(), compute_ece(), load_dataset_questions(), main(), _normalize_row(), Anthropic, Path, Hard dataset calibration benchmark: ARC-Challenge, HellaSwag, WinoGrande, BIG-… (+5 more)

### Community 75 - "claude_to_sif.py"
Cohesion: 0.11
Nodes (26): cold_start(), get_sif_from_agent_a(), main(), Anthropic, Multi-agent handoff experiment: SIF as the handoff artifact between models.…, Agent B resumes from SIF trace., Agent B resumes from flat JSON dump (same data, no types)., Agent B answers from scratch with no context. (+18 more)

### Community 76 - "package.json"
Cohesion: 0.14
Nodes (13): author, description, engines, node, exports, homepage, license, main (+5 more)

### Community 77 - "_write_spif"
Cohesion: 0.17
Nodes (6): SPIFDocument, Tests for spfx render warning and spfx export command., TestExportLosslessJson, TestExportMsgpack, TestRenderWarning, _write_spif()

### Community 78 - "run_full_comparison"
Cohesion: 0.21
Nodes (13): bench_fn(), compare_roundtrip_fidelity(), compare_sizes(), compare_speed(), compare_tamper_detection(), SPIFDocument, Mean microseconds per call., Compare sizes across all formats. (+5 more)

### Community 79 - "SPIFStreamWriter"
Cohesion: 0.24
Nodes (7): sha256(), sha256Sync(), concat(), makeChunk(), makeRawChunk(), SPIFStreamWriter, Provenance

### Community 80 - "SPIFStreamReader"
Cohesion: 0.13
Nodes (11): main(), Live demo: Claude API → streaming SPIF → terminal + saved file. Run:…, main(), Live demo: OpenAI API → streaming SPIF → terminal + saved file. Run:…, Incremental SPIF stream reader. Call feed(bytes) with however many bytes have…, Feed bytes. Returns any events emitted during this call. After an "error" or…, True once a "verified" or "error" event has been emitted., An event emitted by SPIFStreamReader as bytes arrive. type values: "opened" —… (+3 more)

### Community 81 - "SPIFWriter"
Cohesion: 0.15
Nodes (22): _chain_with_cycle_at_end(), _linear_no_cycle(), main(), Test 4 — DAG DoS Safety. Build a 10k-node linear trace chain with a cycle…, Parameters ---------- compress : If True, compress chunk payloads with zlib.…, SPIFWriter, _linear_trace_doc(), Roadmap item: benchmark DAG cycle-detection to confirm O(N) behavior (DoS… (+14 more)

### Community 82 - "TestKeyManagement"
Cohesion: 0.14
Nodes (3): _alice_pub(), TestKeyManagement, TestRevocation

### Community 83 - "Format Comparison"
Cohesion: 0.17
Nodes (11): Format Comparison, Format Comparison Insights, Key Findings, LLM Judge Insights, Roundtrip Fidelity (1.0 = full preservation), SIF Advantages, SIF Hard Benchmark Report, Size Comparison (bytes) (+3 more)

### Community 84 - "Key Findings"
Cohesion: 0.17
Nodes (11): 1. Semantic Fidelity, 2. Size Efficiency, 3. Performance (μs roundtrip), 4. Integrity & Security, 5. SIF-Specific Strengths, Key Findings, Methodology Notes, Overview (+3 more)

### Community 85 - "Quickstart"
Cohesion: 0.17
Nodes (11): Error types, License, OpenAI adapter, Python interop, Quickstart, Read a SPIF file, spif-js, Streaming (+3 more)

### Community 86 - "6. Chunk Payload Schemas"
Cohesion: 0.17
Nodes (12): 6.10 TASK (`0x09`) — v1.1, 6.11 CHECKSUM (`0xFF`), 6.1 HEADER (`0x00`), 6.2 PROVENANCE (`0x01`), 6.3 SEMANTIC (`0x02`), 6.4 TRACE (`0x03`), 6.5 PAYLOAD (`0x04`), 6.6 ALTS (`0x05`) (+4 more)

### Community 87 - "test_c2pa_watermark_edge.py"
Cohesion: 0.27
Nodes (11): _generate_ed25519_key(), Ed25519PrivateKey, SPIFDocument, Advanced C2PA and Watermarking Edge Case Security Tests. Covers state-of-the-…, Verifies the Defense-in-Depth threat model (EU AI Act v2026/C2PA): If an…, Simulates C2PA v2.3 manifest assertions (actions, binding, digital certificate)…, Test that 'Provenance Piggybacking' (where an attacker takes a valid signature…, _sign_document() (+3 more)

### Community 88 - "_key_slug"
Cohesion: 0.20
Nodes (6): Ed25519PublicKey, _key_slug(), Remove the public key for key_id. Returns True if it existed., Convert a key_id to a safe filename stem., Register a public key under the given key_id. Parameters ---------- key_id : A…, TestKeySlug

### Community 89 - "mlflow_adapter.py"
Cohesion: 0.27
Nodes (7): demo_manual(), demo_wrapper(), SPIFDocument, MLflow + SPIF — tamper-evident AI output logging for model deployment…, Wraps any LLM callable. On each call: 1. Calls the underlying model. 2. Wraps…, _response_to_spif(), SPIFMLflowLogger

### Community 90 - "adversarial_stress_test.py"
Cohesion: 0.28
Nodes (8): Test 2: Corruption Susceptibility Flip random bits. Does the parser return…, Test 3: Truncation / Degradation Cut the file in half., Lossy conversion to dict for other formats., Test 1: Spoofing/Hackability Can we change 'ALLOW_ACCESS_TO_RESOURCES' to…, test_corruption_susceptibility(), test_degradation_robustness(), test_hackability(), to_dict()

### Community 91 - "calibration_study.py"
Cohesion: 0.29
Nodes (10): ask_with_confidence(), bucket_calibration(), check_correctness(), main(), Anthropic, Calibration study: do SIF Distribution confidence values track actual accuracy?…, Ask Claude a factual question and ask it to report its confidence. Returns…, Simple substring check (case-insensitive). (+2 more)

### Community 92 - "resumability_study.py"
Cohesion: 0.31
Nodes (10): answers_match(), get_trace_and_answer(), main(), Anthropic, Resumability study: can a SIF trace enable a second model to continue reasoning…, Check if two answers agree by counting keyword overlap. Returns (match,…, Ask Claude with extended thinking. Returns (thinking_blocks, final_answer)., Give the second model a truncated trace and ask it to continue. Uses only the… (+2 more)

### Community 93 - "tamper_demo.py"
Cohesion: 0.33
Nodes (10): attack_bit_flip(), attack_confidence_inflation(), attack_provenance_spoof(), main(), _make_signed_doc(), print_summary(), Ed25519PrivateKey, Tamper evidence demo: what SIF detects that JSON cannot. Three attack… (+2 more)

### Community 94 - "devDependencies"
Cohesion: 0.18
Nodes (11): jest, @jest/globals, devDependencies, jest, @jest/globals, ts-jest, @types/node, typescript (+3 more)

### Community 95 - "keywords"
Cohesion: 0.18
Nodes (11): keywords, agents, ai, audit, binary-format, compliance, ed25519, llm (+3 more)

### Community 96 - "agent_chain_e2e.py"
Cohesion: 0.31
Nodes (9): build_chain(), main(), _make_signer(), SPIFDocument, Test 6 — Agent Chain E2E. Simulates: Claude produces a SPIF doc -> GPT-4o reads…, Two-pass ed25519 sign — locks body layout, then signs the real bytes., Verify every hop: signature valid AND context_ref matches the prior hop's…, _sign() (+1 more)

### Community 97 - "_make_demo_file"
Cohesion: 0.33
Nodes (9): generate_compliance_report(), _identify_gaps(), main(), _make_demo_file(), print_report(), Path, EU AI Act / NIST AI RMF compliance report generator for SIF files. Takes a .sif…, Read a SIF file and produce a structured compliance report. All checks are… (+1 more)

### Community 98 - "mmlu_bench.py"
Cohesion: 0.38
Nodes (9): ask_mmlu(), check_correct(), compute_ece(), load_mmlu(), main(), Anthropic, Path, MMLU calibration benchmark: 57-subject multiple-choice, stored as SIF. MMLU… (+1 more)

### Community 99 - "jest"
Cohesion: 0.20
Nodes (10): jest, extensionsToTreatAsEsm, moduleNameMapper, preset, testEnvironment, transform, ^(\\.{1,2}/.*)\\.js$, ^.+\\.tsx?$ (+2 more)

### Community 100 - "_make_doc"
Cohesion: 0.33
Nodes (5): _make_doc(), SPIFDocument, Two-pass signing matching the SPIF wire contract. The signature covers all…, _sign_doc(), TestVerification

### Community 101 - "test_tamper_latency.py"
Cohesion: 0.38
Nodes (9): _doc(), SPIFDocument, Roadmap item: measure tamper-detection latency for integrity validation.…, _tamper(), test_tamper_detection_latency_scales_with_size_not_blowup(), test_tamper_detection_latency_stays_bounded_small_doc(), test_tampered_document_rejected_via_checksum(), _time_tamper_detection() (+1 more)

### Community 102 - "bench_speed_percentiles.py"
Cohesion: 0.29
Nodes (11): _bench(), _full_doc(), main(), _minimal_doc(), _percentiles(), SPIFDocument, Test 3 — Sub-100µs + 450k/sec, with real percentiles and a cost breakdown.…, _sign() (+3 more)

### Community 103 - "SPIF — Semantic Provenance Inference Format"
Cohesion: 0.22
Nodes (8): CLI, Dependencies, Key conventions, Lint, Setup, SPIF — Semantic Provenance Inference Format, Structure, Tests

### Community 104 - "Detailed Findings"
Cohesion: 0.22
Nodes (9): 1. Signature Implementation (spif/reader.py, lines 532-613), 2. Checksum Implementation (spif/reader.py, lines 325-334), 3. Key Derivation (spif/crypto.py, lines 20-38), 4. Revocation Mechanism (spif/crypto.py, lines 71-97), 5. Signature Escrow / Two-Pass Signing Pattern, 6. CBOR Encoding Stability, 7. Real-World Threat Modeling, 8. Dependency Security (+1 more)

### Community 105 - "SPIF — Semantic Provenance Inference Format"
Cohesion: 0.22
Nodes (9): Audit Chains, Install, Language Support, License, Specification, SPIF — Semantic Provenance Inference Format, The Problem, Why Not JSON + HMAC? (+1 more)

### Community 106 - "SPIF v0.2.0 (proposed)"
Cohesion: 0.22
Nodes (8): Caveats, Highlights, Install, Quickstart, Security note, SPIF v0.2.0 (proposed), Tested providers, What’s new since last cut

### Community 107 - "5. Data Types"
Cohesion: 0.22
Nodes (9): 5.1 Distribution, 5.2 Node, 5.3 Node Types, 5.4 TraceStep, 5.5 Provenance, 5.6 SemanticLayer, 5.7 Alternative, 5.8 Signature (+1 more)

### Community 108 - "test_cross_language_cbor.py"
Cohesion: 0.28
Nodes (8): fixture, SPIFDocument, Roadmap item: validate CBOR tagging across languages for interoperability.…, Sanity control: the same document must round-trip in Python too., spif_viewer_bin(), _tagged_doc(), test_python_encoded_tags_decode_in_rust(), test_python_encoded_tags_still_decode_in_python()

### Community 109 - "SPIF Cryptographic Implementation Audit"
Cohesion: 0.25
Nodes (5): Executive Summary, Final Assessment, Recommendations for v1.0, SPIF Cryptographic Implementation Audit, Test Statistics

### Community 110 - "SidecarHTTPHandler"
Cohesion: 0.27
Nodes (5): Any, BaseHTTPRequestHandler, Validate a SPIF payload against the configuration policy and CRL. Returns a…, HTTP Handler for verification endpoint and reverse proxy verification., SidecarHTTPHandler

### Community 111 - "bench_token_cost.py"
Cohesion: 0.40
Nodes (9): count_tokens(), make_spif_doc(), SPIFDocument, Token Cost Benchmark — Scenarios D, E & F…, Compact canonical JSON that preserves every SPIF field without base64.…, scenario_d(), scenario_e(), scenario_f() (+1 more)

### Community 112 - "TestChecksumCompleteness"
Cohesion: 0.36
Nodes (4): Flipping each bit before the CHECKSUM chunk must invalidate the checksum. We…, Modifying the checksum payload itself must raise SPIFChecksumError (the stored…, Bytes after the CHECKSUM chunk are outside the checksum scope. A reader MUST…, TestChecksumCompleteness

### Community 113 - "10. Streaming Protocol (SSPIF)"
Cohesion: 0.29
Nodes (7): 10.1 Stream Wire Format, 10.2 PARTIAL_TEXT Chunk (`0x10`), 10.3 STREAM_RESUME Chunk (`0x12`), 10.4 Resume Token Format, 10.5 Resume Protocol, 10.6 Stream Reader Events, 10. Streaming Protocol (SSPIF)

### Community 114 - ".test_checksum_chunk_body_replacement_detected"
Cohesion: 0.40
Nodes (3): The SIF reader stops reading at the CHECKSUM chunk. Appending garbage after it…, Changing the stored checksum bytes to garbage is detected as SPIFChecksumError., TestLengthExtension

### Community 115 - "_sign_doc"
Cohesion: 0.33
Nodes (5): Ed25519PrivateKey, Sign with key A, but put key B's public key as the signer. verify_signature…, Two-pass signing — mirrors test_signature.py helper., _sign_doc(), TestWrongKeyID

### Community 117 - "pytest_collection_modifyitems"
Cohesion: 0.33
Nodes (5): Config, Item, Parser, pytest_addoption(), pytest_collection_modifyitems()

### Community 118 - "Quickstart"
Cohesion: 0.33
Nodes (6): CLI, Quickstart, Sign the output, Verify, Wrap an Anthropic response, Wrap an OpenAI response

### Community 119 - "12. Conformance"
Cohesion: 0.33
Nodes (6): 12.1 Reader MUST, 12.2 Reader SHOULD, 12.3 Reader MAY, 12.4 Writer MUST, 12.5 Writer SHOULD, 12. Conformance

### Community 120 - "7. Integrity and Authentication"
Cohesion: 0.40
Nodes (5): 7.1 Checksum, 7.2 Signature, 7.3 Strict Mode, 7.4 Key Management, 7. Integrity and Authentication

### Community 121 - "otel.py"
Cohesion: 0.40
Nodes (4): _infer_system(), _make_span_id(), SIF → OpenTelemetry GenAI semantic conventions exporter. Maps a SPIFDocument to…, Map model name to OTel gen_ai.system value.

### Community 122 - ".test_checksum_tamper_raises_not_asserts"
Cohesion: 0.40
Nodes (3): Structural test: the reader module must import hmac and use compare_digest for…, A single-byte flip in the checksum bytes raises SPIFChecksumError specifically…, TestTimingSafety

### Community 123 - "scripts"
Cohesion: 0.50
Nodes (4): scripts, build, prepublishOnly, test

### Community 124 - "2. File Layout"
Cohesion: 0.50
Nodes (4): 2.1 Magic Bytes, 2.2 Version Byte, 2.3 Flags Byte, 2. File Layout

### Community 125 - "dependencies"
Cohesion: 0.67
Nodes (3): cbor-x, dependencies, cbor-x

### Community 127 - "files"
Cohesion: 0.67
Nodes (3): files, dist, README.md

### Community 128 - "repository"
Cohesion: 0.67
Nodes (3): repository, type, url

### Community 130 - "4. CBOR Encoding"
Cohesion: 0.67
Nodes (3): 4.1 Canonical Mode, 4.2 Custom CBOR Tags, 4. CBOR Encoding

### Community 137 - "prov.py"
Cohesion: 0.50
Nodes (3): _ms_to_iso(), SIF → W3C PROV-JSON exporter. Maps a SPIFDocument to a PROV-JSON dict per:…, Convert millisecond timestamp to ISO 8601 string.

### Community 138 - "TestRoundTripLoss"
Cohesion: 0.50
Nodes (3): Demonstrate that neither OTel nor PROV can round-trip back to SIF without loss., After OTel export, you cannot tell a Distribution from a plain float., TestRoundTripLoss

## Knowledge Gaps
- **220 isolated node(s):** `MAGIC`, `SUPPORTED_VERSIONS`, `CHUNK_NAMES`, `Distribution`, `NodeRef` (+215 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `SPIFReader` connect `SPIFReader` to `SPIFDocument`, `SemanticLayer`, `SPIFDocument`, `reader.py`, `streaming.py`, `Node`, `Provenance`, `live_failure_telemetry_bench.py`, `tamper_detection_compare.py`, `gemini_adapter.py`, `SPIFKeyStore`, `OpenAISPIFAdapter`, `Signature`, `synthetic_generators.py`, `Distribution`, `full_bench.py`, `AnthropicSPIFAdapter`, `SPIFDocument`, `openai_adapter.py`, `bench_realworld.py`, `otel_vs_spif_bench.py`, `GeminiSPIFAdapter`, `live_api_bench.py`, `SPIFStreamWriter`, `audit_chain_bench.py`, `test_keystore.py`, `Alternative`, `iter_events`, `ai_native_bench.py`, `cli.py`, `SPIFRenderer`, `test_gemini_adapter.py`, `test_hardening_scenarios.py`, `test_elite_challenges.py`, `generate_compat_fixtures.py`, `format_comparator.py`, `test_hardening.py`, `bench_size.py`, `test_real_world_acceptance.py`, `adversarial_resistance_bench.py`, `.decode`, `_make_key`, `test_signature.py`, `llm_judge_runner.py`, `test_live_provider_acceptance.py`, `_parse_resume_token`, `test_task_chunk.py`, `compute_content_id`, `test_fuzz.py`, `.test_strip_sig_chunk_verify_returns_false`, `test_rust_sidecar.py`, `_minimal_doc`, `eu_ai_act_audit.py`, `SPIFStreamReader`, `SPIFWriter`, `test_c2pa_watermark_edge.py`, `mlflow_adapter.py`, `agent_chain_e2e.py`, `test_tamper_latency.py`, `bench_speed_percentiles.py`, `test_cross_language_cbor.py`, `SidecarHTTPHandler`, `bench_token_cost.py`, `TestChecksumCompleteness`, `.test_checksum_chunk_body_replacement_detected`, `_sign_doc`, `._inject_and_decode`, `.test_checksum_tamper_raises_not_asserts`?**
  _High betweenness centrality (0.138) - this node is a cross-community bridge._
- **Why does `Distribution` connect `Distribution` to `SPIFDocument`, `SemanticLayer`, `test_model_comprehension.py`, `SPIFDocument`, `reader.py`, `streaming.py`, `sif_reader.ts`, `Node`, `Provenance`, `live_failure_telemetry_bench.py`, `tamper_detection_compare.py`, `gemini_adapter.py`, `TestRoundTripLoss`, `OpenAISPIFAdapter`, `Signature`, `synthetic_generators.py`, `to_otel_span`, `openai_adapter.py`, `SPIFReader`, `bench_realworld.py`, `otel_vs_spif_bench.py`, `GeminiSPIFAdapter`, `test_tool_adapters.py`, `audit_chain_bench.py`, `test_keystore.py`, `Alternative`, `_doc_full`, `iter_events`, `ai_native_bench.py`, `cli.py`, `SPIFRenderer`, `anthropic_adapter.py`, `test_gemini_adapter.py`, `test_hardening_scenarios.py`, `test_elite_challenges.py`, `generate_compat_fixtures.py`, `format_comparator.py`, `calibration_bench.py`, `bench_size.py`, `test_real_world_acceptance.py`, `adversarial_resistance_bench.py`, `.decode`, `test_task_chunk.py`, `doc_full`, `compute_content_id`, `test_fuzz.py`, `test_rust_sidecar.py`, `_minimal_doc`, `eu_ai_act_audit.py`, `hard_bench.py`, `claude_to_sif.py`, `_write_spif`, `SPIFWriter`, `test_c2pa_watermark_edge.py`, `mlflow_adapter.py`, `calibration_study.py`, `resumability_study.py`, `tamper_demo.py`, `_make_demo_file`, `mmlu_bench.py`, `_make_doc`, `bench_speed_percentiles.py`, `test_cross_language_cbor.py`, `SidecarHTTPHandler`, `bench_token_cost.py`, `._inject_and_decode`?**
  _High betweenness centrality (0.103) - this node is a cross-community bridge._
- **Why does `SPIFWriter` connect `SPIFWriter` to `SPIFDocument`, `SemanticLayer`, `test_model_comprehension.py`, `SPIFDocument`, `reader.py`, `streaming.py`, `Node`, `Provenance`, `live_failure_telemetry_bench.py`, `tamper_detection_compare.py`, `gemini_adapter.py`, `OpenAISPIFAdapter`, `Signature`, `synthetic_generators.py`, `Distribution`, `full_bench.py`, `AnthropicSPIFAdapter`, `SPIFDocument`, `openai_adapter.py`, `SPIFReader`, `bench_realworld.py`, `otel_vs_spif_bench.py`, `GeminiSPIFAdapter`, `live_api_bench.py`, `audit_chain_bench.py`, `test_keystore.py`, `iter_events`, `ai_native_bench.py`, `cli.py`, `SPIFRenderer`, `anthropic_adapter.py`, `test_gemini_adapter.py`, `test_hardening_scenarios.py`, `test_elite_challenges.py`, `generate_compat_fixtures.py`, `format_comparator.py`, `test_hardening.py`, `bench_size.py`, `test_real_world_acceptance.py`, `adversarial_resistance_bench.py`, `_make_key`, `test_signature.py`, `langchain_adapter.py`, `test_live_provider_acceptance.py`, `test_task_chunk.py`, `hard_sif_bench.py`, `compute_content_id`, `test_fuzz.py`, `.test_strip_sig_chunk_verify_returns_false`, `test_rust_sidecar.py`, `_minimal_doc`, `eu_ai_act_audit.py`, `claude_to_sif.py`, `_write_spif`, `run_full_comparison`, `test_c2pa_watermark_edge.py`, `mlflow_adapter.py`, `agent_chain_e2e.py`, `_make_doc`, `test_tamper_latency.py`, `bench_speed_percentiles.py`, `test_cross_language_cbor.py`, `SidecarHTTPHandler`, `bench_token_cost.py`, `TestChecksumCompleteness`, `.test_checksum_chunk_body_replacement_detected`, `_sign_doc`, `._inject_and_decode`, `.test_checksum_tamper_raises_not_asserts`?**
  _High betweenness centrality (0.087) - this node is a cross-community bridge._
- **Are the 41 inferred relationships involving `SPIFReader` (e.g. with `AnthropicBench` and `OpenAIBench`) actually correct?**
  _`SPIFReader` has 41 INFERRED edges - model-reasoned connections that need verification._
- **Are the 30 inferred relationships involving `Node` (e.g. with `SPIFChatModel` and `SPIFLLMWrapper`) actually correct?**
  _`Node` has 30 INFERRED edges - model-reasoned connections that need verification._
- **Are the 27 inferred relationships involving `SPIFWriter` (e.g. with `AnthropicBench` and `OpenAIBench`) actually correct?**
  _`SPIFWriter` has 27 INFERRED edges - model-reasoned connections that need verification._
- **Are the 65 inferred relationships involving `Distribution` (e.g. with `BenchResult` and `FormatStats`) actually correct?**
  _`Distribution` has 65 INFERRED edges - model-reasoned connections that need verification._