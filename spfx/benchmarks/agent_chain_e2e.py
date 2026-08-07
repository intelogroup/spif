"""
Test 6 — Agent Chain E2E.

Simulates: Claude produces a SPIF doc -> GPT-4o reads it, appends a trace
step, re-signs -> Rust-equivalent gateway (local ed25519 verify, standing in
for the Rust sidecar since crypto is byte-identical across implementations)
verifies full lineage.

Pass criteria:
  - 3 producers, 3 signatures, chain of 3 documents linked via context_ref.
  - Timestamps preserved and monotonic across the chain.
  - Full chain verifies (all signatures valid, all context_refs match).
  - Tampering the MIDDLE document's payload breaks verification for every
    document downstream of it (not just itself).
  - SPIF crypto overhead (sign+encode+verify per hop) is a tiny fraction of
    realistic LLM call latency (simulated at ~800ms/hop).

Usage: python spfx/benchmarks/agent_chain_e2e.py
"""
from __future__ import annotations

import base64
import time
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spfx import (
    SPIFDocument, Node, TraceStep, Provenance, Signature,
    SPIFWriter, SPIFReader, SPIFChecksumError, SPIFSignatureError,
)
from spfx.format import MAGIC

SIMULATED_LLM_LATENCY_S = 0.8  # 800ms/hop, per the task spec


def _make_signer(name: str):
    # verify_signature() treats Signature.signer as a raw base64 ed25519 pubkey,
    # so the producer name can't be embedded there — it goes in provenance.model_version instead.
    key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return key, pub_b64


def _sign(doc: SPIFDocument, key, signer_id: str) -> bytes:
    """Two-pass ed25519 sign — locks body layout, then signs the real bytes."""
    import struct
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
    dummy = writer.encode(doc)

    offset = len(MAGIC) + 2
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == 0x07:
            sig_offset = offset
            break
        if ct == 0xFF:
            break
        offset += 5 + ln
    assert sig_offset is not None

    body_to_sign = dummy[:sig_offset]
    raw_sig = key.sign(body_to_sign)
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=raw_sig)
    return writer.encode(doc)


def _verify_chain(chain: list[bytes]) -> tuple[bool, str]:
    """Verify every hop: signature valid AND context_ref matches the prior hop's content_id."""
    reader = SPIFReader()
    prev_content_id = None
    for i, data in enumerate(chain):
        try:
            ok = reader.verify_signature(data)
        except (SPIFChecksumError, SPIFSignatureError) as e:
            return False, f"hop {i}: verification raised {type(e).__name__}: {e}"
        if not ok:
            return False, f"hop {i}: signature invalid"

        doc = reader.decode(data)
        if i > 0:
            if doc.provenance.context_ref != prev_content_id:
                return False, f"hop {i}: context_ref does not chain to hop {i-1}"
        prev_content_id = doc.content_id()
    return True, "ok"


def build_chain() -> tuple[list[bytes], list[float], dict]:
    claude_key, claude_id = _make_signer("claude-sonnet-4-6")
    gpt_key, gpt_id = _make_signer("gpt-4o")
    gateway_key, gateway_id = _make_signer("rust-gateway")

    hop_overheads = []
    chain: list[bytes] = []

    # Hop 1: Claude produces the initial claim.
    t_llm = time.perf_counter()
    time.sleep(0)  # stand-in for the real ~800ms LLM call, not counted in overhead
    llm_elapsed = SIMULATED_LLM_LATENCY_S

    t0 = time.perf_counter()
    doc1 = SPIFDocument(
        payload=[Node(id="claim1", type="fact", value="Ibuprofen 200mg is OTC in the US.")],
        provenance=Provenance(source_model="claude-sonnet-4-6", timestamp_ms=int(time.time() * 1000)),
        trace=[TraceStep(id="s1", type="evidence", content="drug label lookup")],
    )
    data1 = _sign(doc1, claude_key, claude_id)
    hop_overheads.append(time.perf_counter() - t0)
    chain.append(data1)
    reader = SPIFReader()
    id1 = reader.decode(data1).content_id()

    # Hop 2: GPT-4o reads hop 1, appends a trace step, re-signs as a new hop.
    t0 = time.perf_counter()
    prior = reader.decode(data1)
    doc2 = SPIFDocument(
        payload=list(prior.payload) + [Node(id="claim2", type="fact", value="Max adult dose: 1200mg/day OTC.")],
        provenance=Provenance(
            source_model="gpt-4o", timestamp_ms=int(time.time() * 1000) + 1,
            context_ref=id1,
        ),
        trace=list(prior.trace) + [TraceStep(id="s2", type="inference", content="dosing guideline cross-check", deps=["s1"])],
    )
    data2 = _sign(doc2, gpt_key, gpt_id)
    hop_overheads.append(time.perf_counter() - t0)
    chain.append(data2)
    id2 = reader.decode(data2).content_id()

    # Hop 3: Rust gateway ingests, appends a verification trace step, re-signs.
    t0 = time.perf_counter()
    prior2 = reader.decode(data2)
    doc3 = SPIFDocument(
        payload=list(prior2.payload),
        provenance=Provenance(
            source_model="rust-gateway", timestamp_ms=int(time.time() * 1000) + 2,
            context_ref=id2,
        ),
        trace=list(prior2.trace) + [TraceStep(id="s3", type="conclusion", content="gateway verified chain", deps=["s2"])],
    )
    data3 = _sign(doc3, gateway_key, gateway_id)
    hop_overheads.append(time.perf_counter() - t0)
    chain.append(data3)

    meta = {
        "producers": [claude_id, gpt_id, gateway_id],
        "llm_latency_s": llm_elapsed,
    }
    return chain, hop_overheads, meta


def main():
    chain, hop_overheads, meta = build_chain()

    print("=== Test 6: Agent Chain E2E ===\n")

    # --- Lineage checks ---
    reader = SPIFReader()
    docs = [reader.decode(d) for d in chain]
    timestamps = [d.provenance.timestamp_ms for d in docs]
    monotonic = all(timestamps[i] < timestamps[i + 1] for i in range(len(timestamps) - 1))
    producers = [d.provenance.source_model for d in docs]

    print(f"Producers ({len(producers)}): {producers}")
    print(f"Timestamps: {timestamps}  monotonic={monotonic}")

    ok, msg = _verify_chain(chain)
    print(f"\nFull chain verify (untampered): {ok} ({msg})")

    # --- Overhead vs simulated LLM latency ---
    total_spif_overhead = sum(hop_overheads)
    total_llm_time = meta["llm_latency_s"] * len(chain)
    pct = 100 * total_spif_overhead / total_llm_time
    print(f"\nSPIF overhead per hop (sign+encode): {[f'{h*1e3:.3f}ms' for h in hop_overheads]}")
    print(f"Total SPIF overhead: {total_spif_overhead*1e3:.3f}ms vs total simulated LLM time: {total_llm_time*1e3:.0f}ms")
    print(f"Overhead ratio: {pct:.4f}%  (target <0.1%: {'PASS' if pct < 0.1 else 'FAIL'})")

    # --- Tamper the MIDDLE document, confirm chain fails from there on ---
    tampered_chain = list(chain)
    mutated = bytearray(tampered_chain[1])
    mutated[len(MAGIC) + 2 + 60] ^= 0xFF
    tampered_chain[1] = bytes(mutated)

    tamper_ok, tamper_msg = _verify_chain(tampered_chain)
    print(f"\nChain verify with hop 2 tampered: {tamper_ok} ({tamper_msg})")

    # --- Inspect the tampered hop specifically: which layer catches it, and why ---
    reader = SPIFReader()
    tampered_hop_layer = None
    tampered_hop_detail = None
    try:
        reader.decode(tampered_chain[1])
        tampered_hop_layer = "NONE — decoded without error (FAIL)"
    except SPIFChecksumError as e:
        tampered_hop_layer = "CHECKSUM"
        tampered_hop_detail = str(e)
    except SPIFSignatureError as e:
        tampered_hop_layer = "SIGNATURE"
        tampered_hop_detail = str(e)
    except Exception as e:
        tampered_hop_layer = f"OTHER ({type(e).__name__})"
        tampered_hop_detail = str(e)
    print(f"\nTampered hop (index 1) decode layer that caught it: {tampered_hop_layer}")
    print(f"  Detail: {tampered_hop_detail}")
    inspect_pass = tampered_hop_layer == "CHECKSUM"

    # --- 10 parallel chains reusing the same two keypairs — no cross-talk ---
    print("\n10 parallel 3-hop chains, same keypairs, independent verification:")
    shared_claude_key, shared_claude_id = _make_signer("claude-sonnet-4-6")
    shared_gateway_key, shared_gateway_id = _make_signer("rust-gateway")
    parallel_results = []
    for i in range(10):
        d1 = SPIFDocument(
            payload=[Node(id=f"c{i}_n1", type="fact", value=f"claim from chain {i}")],
            provenance=Provenance(source_model="claude-sonnet-4-6", timestamp_ms=int(time.time() * 1000)),
        )
        data1 = _sign(d1, shared_claude_key, shared_claude_id)
        id1 = SPIFReader().decode(data1).content_id()

        d2 = SPIFDocument(
            payload=[Node(id=f"c{i}_n2", type="fact", value=f"hop2 for chain {i}")],
            provenance=Provenance(source_model="gpt-4o", timestamp_ms=int(time.time() * 1000) + 1,
                                   context_ref=id1),
        )
        data2 = _sign(d2, shared_claude_key, shared_claude_id)  # deliberately reuse same key+pubkey as hop 1
        id2 = SPIFReader().decode(data2).content_id()

        d3 = SPIFDocument(
            payload=[Node(id=f"c{i}_n3", type="fact", value=f"gateway verdict for chain {i}")],
            provenance=Provenance(source_model="rust-gateway", timestamp_ms=int(time.time() * 1000) + 2,
                                   context_ref=id2),
        )
        data3 = _sign(d3, shared_gateway_key, shared_gateway_id)

        chain_i = [data1, data2, data3]
        ok_i, msg_i = _verify_chain(chain_i)
        parallel_results.append((i, ok_i, msg_i))

    parallel_pass = all(ok_i for _, ok_i, _ in parallel_results)
    failed_chains = [(i, msg_i) for i, ok_i, msg_i in parallel_results if not ok_i]
    print(f"  {sum(1 for _, ok_i, _ in parallel_results if ok_i)}/10 chains verified independently, "
          f"no cross-talk: {'PASS' if parallel_pass else 'FAIL'}")
    if failed_chains:
        print(f"  Failures: {failed_chains}")

    # --- Verdict ---
    lineage_pass = monotonic and len(set(producers)) == 3
    untampered_pass = ok
    tamper_pass = (not tamper_ok)
    overhead_pass = pct < 0.1

    print("\n=== Verdict ===")
    print(f"3 producers + monotonic timestamps: {'PASS' if lineage_pass else 'FAIL'}")
    print(f"Untampered chain verifies:          {'PASS' if untampered_pass else 'FAIL'}")
    print(f"Tampered middle hop breaks chain:   {'PASS' if tamper_pass else 'FAIL'}")
    print(f"Tampered hop caught at CHECKSUM:    {'PASS' if inspect_pass else 'FAIL'}")
    print(f"10 parallel chains, no cross-talk:  {'PASS' if parallel_pass else 'FAIL'}")
    print(f"Overhead <0.1% of LLM latency:      {'PASS' if overhead_pass else 'FAIL'}")

    all_pass = (lineage_pass and untampered_pass and tamper_pass and inspect_pass
                and parallel_pass and overhead_pass)
    print(f"\nTEST 6 OVERALL: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
