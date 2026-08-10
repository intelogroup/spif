"""
Provenance comparison benchmark: SPIF vs. real provenance/attestation systems.

SPIF's claim isn't "faster than JSON" — it's "cheap enough to attach provenance
inline, at generation time, per AI output." The relevant competitors are
provenance/attestation systems, not serialization formats:

  - in-toto     — supply-chain link/layout attestations, DSSE envelope, local
                  key signing, offline-capable.
  - C2PA        — content credentials (Content Authenticity Initiative),
                  embeds a signed manifest (claim + assertions) into media,
                  offline-capable with a supplied signing cert.
  - Sigstore    — keyless signing via Fulcio (short-lived cert issuance) +
                  Rekor (public transparency log). NOT measured quantitatively
                  here: its guarantee model requires a network round-trip to
                  public infra for both signing and verification. That's an
                  architectural cost, not a local CPU cost, so a local-only
                  microbenchmark would misrepresent it. Documented instead of
                  measured — see the printed note.

Same payload used for all three quantitative systems: one "AI response with
metadata" record, comparable to a single hop in audit_chain_bench.py. Both
SPIF and in-toto measure a *signed* build/verify round trip (ed25519) —
comparing an unsigned SPIF encode against a signed DSSE envelope would
understate SPIF's real per-record cost.

Usage:
    /path/to/venv/bin/python3 benchmarks/provenance_comparison_bench.py [--reps N]

Requires (in the venv, not spif's normal deps): securesystemslib, c2pa-python.
c2pa-python needs Python >=3.10 (uses `match` statements internally).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from spif import SPIFDocument, SPIFWriter, SPIFReader, Node, compute_content_id
from spif.types import Distribution, Provenance
from spif.crypto import generate_key, sign_document

PAYLOAD_TEXT = (
    "The model recommends approach B because it minimizes latency under the "
    "given constraints while preserving accuracy within the required bound."
)
MODEL = "claude-sonnet-4-6"
TIMESTAMP_MS = 1_700_000_000_000


def _percentile(samples: list[float], p: float) -> float:
    s = sorted(samples)
    k = (len(s) - 1) * p
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def _timeit(fn, reps: int) -> dict:
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1e6)  # µs
    return {
        "mean_us": statistics.mean(samples),
        "p50_us": _percentile(samples, 0.5),
        "p99_us": _percentile(samples, 0.99),
    }


# ---------------------------------------------------------------------------
# SPIF
# ---------------------------------------------------------------------------

def _spif_doc() -> SPIFDocument:
    return SPIFDocument(
        payload=[
            Node(
                id="response",
                type="text",
                value=PAYLOAD_TEXT,
                confidence=Distribution(mean=0.85, var=0.03, shape="gaussian",
                                        semantics="output_stability"),
            )
        ],
        provenance=Provenance(
            source_model=MODEL,
            model_version=MODEL,
            temperature=0.7,
            input_hash=hashlib.sha256(PAYLOAD_TEXT.encode()).hexdigest(),
            timestamp_ms=TIMESTAMP_MS,
        ),
    )


def spif_build_and_sign(private_key) -> bytes:
    # Signed, like in-toto's build below — an unsigned SPIF encode isn't a
    # fair comparison against a signed DSSE envelope.
    return sign_document(_spif_doc(), private_key)


def spif_verify(blob: bytes) -> bool:
    return SPIFReader().verify_signature(blob)


# ---------------------------------------------------------------------------
# in-toto — DSSE-enveloped link attestation, local Ed25519 key
# ---------------------------------------------------------------------------

def _in_toto_setup():
    from securesystemslib.signer import CryptoSigner
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    signer = CryptoSigner(priv, None)
    return signer


def _in_toto_statement() -> bytes:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "response", "digest": {"sha256": hashlib.sha256(PAYLOAD_TEXT.encode()).hexdigest()}}],
        "predicateType": "https://spif.dev/ai-provenance/v1",
        "predicate": {
            "source_model": MODEL,
            "temperature": 0.7,
            "timestamp_ms": TIMESTAMP_MS,
            "text": PAYLOAD_TEXT,
        },
    }
    return json.dumps(statement).encode()


def in_toto_build_and_sign(signer) -> bytes:
    from securesystemslib import dsse

    env = dsse.Envelope(payload=_in_toto_statement(), payload_type="application/vnd.in-toto+json", signatures={})
    env.sign(signer)
    return json.dumps(env.to_dict()).encode()


def in_toto_verify(signer, blob: bytes) -> bool:
    from securesystemslib import dsse

    env = dsse.Envelope.from_dict(json.loads(blob))
    env.verify([signer.public_key], threshold=1)
    return True


# ---------------------------------------------------------------------------
# C2PA — signed manifest, self-signed local cert (offline, no network)
# ---------------------------------------------------------------------------

def _c2pa_setup(tmpdir: Path):
    """Generate a throwaway self-signed cert/key pair for local signing only."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "spif-bench-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        # C2PA's cert profile requires a non-CA leaf with digitalSignature
        # key usage and the content-commitment (emailProtection) EKU.
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    cert_path = tmpdir / "cert.pem"
    key_path = tmpdir / "key.pem"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return cert_path, key_path


def c2pa_build_and_sign(cert_path: Path, key_path: Path, tmpdir: Path) -> Path:
    # C2PA only accepts real media containers (image/audio/video/svg/xml/c2pa) —
    # arbitrary text isn't a supported asset type. SVG is the closest thing to
    # "text content" it will sign, so the payload is embedded as a <desc>.
    import c2pa

    src = tmpdir / "src.svg"
    src.write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg"><desc>{PAYLOAD_TEXT}</desc></svg>'
    )
    dst = tmpdir / f"out_{time.perf_counter_ns()}.svg"

    signer_info = c2pa.C2paSignerInfo(
        alg="es256",
        sign_cert=cert_path.read_bytes(),
        private_key=key_path.read_bytes(),
        ta_url=None,
    )
    manifest = json.dumps({
        "claim_generator": "spif-bench/0.1",
        "assertions": [
            {"label": "ai.provenance", "data": {
                "source_model": MODEL, "temperature": 0.7, "timestamp_ms": TIMESTAMP_MS,
            }},
        ],
    })
    signer = c2pa.Signer.from_info(signer_info)
    with c2pa.Builder.from_json(manifest) as builder:
        builder.sign_file(src, dst, signer)
    return dst


def c2pa_verify(path: Path) -> bool:
    import c2pa
    with c2pa.Reader(str(path)) as reader:
        reader.json()  # raises if manifest missing/invalid
    return True


def _is_expected_c2pa_cert_rejection(error: Exception) -> bool:
    """Return whether C2PA rejected the self-signed certificate as expected."""
    try:
        import c2pa
    except ImportError:
        return False

    if not isinstance(error, c2pa.C2paError):
        return False

    message = str(error).lower()
    return (
        "certificate was self-signed" in message
        or "certificate is invalid" in message
    )


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=100)
    args = ap.parse_args()
    if args.reps <= 0:
        ap.error("--reps must be a positive integer")

    print("\n## Provenance Comparison Benchmark (quantitative: SPIF, in-toto, C2PA)\n")
    print(f"Payload: single AI-response record, {len(PAYLOAD_TEXT)} chars text + metadata. Reps={args.reps}\n")

    results = {}

    # SPIF (signed, ed25519 — same key generated once, outside the timed loop,
    # matching in-toto's setup below)
    spif_key = generate_key()
    build = _timeit(lambda: spif_build_and_sign(spif_key), args.reps)
    blob = spif_build_and_sign(spif_key)
    verify = _timeit(lambda: spif_verify(blob), args.reps)
    results["SPIF"] = {"build": build, "verify": verify, "size_bytes": len(blob)}

    # in-toto
    try:
        signer = _in_toto_setup()
        build = _timeit(lambda: in_toto_build_and_sign(signer), args.reps)
        blob_it = in_toto_build_and_sign(signer)
        verify = _timeit(lambda: in_toto_verify(signer, blob_it), args.reps)
        results["in-toto (DSSE, local Ed25519 key)"] = {"build": build, "verify": verify, "size_bytes": len(blob_it)}
    except Exception as e:
        results["in-toto (DSSE, local Ed25519 key)"] = {"error": str(e)}

    # C2PA — not measured quantitatively either, for a different reason than
    # Sigstore: the native lib refuses to sign with a self-signed certificate
    # at all ("Signature: the certificate was self-signed"), even with a
    # correct BasicConstraints/KeyUsage/EKU profile. Unlike SPIF and in-toto,
    # which sign with a bare local keypair, C2PA requires a CA-chain-issued
    # signing cert (or a configured trust-anchor bundle) before it will
    # produce a manifest at all — there's no bring-your-own-key path to
    # benchmark against. That refusal is itself the finding: see
    # BENCHMARKS.md.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)
        try:
            cert_path, key_path = _c2pa_setup(tmpdir)
            c2pa_build_and_sign(cert_path, key_path, tmpdir)
        except Exception as e:
            if _is_expected_c2pa_cert_rejection(e):
                message = f"requires CA-issued cert, not measured — {e}"
            else:
                message = f"not measured — C2PA setup/signing failed: {e}"
            results["C2PA (signed manifest)"] = {"error": message}
        else:
            # Self-signed cert was unexpectedly accepted — this is a real
            # result worth reporting, not the documented rejection case.
            raise AssertionError(
                "C2PA accepted the self-signed cert — this contradicts the "
                "documented finding, re-check BENCHMARKS.md"
            )

    hdr = f"{'System':<42}{'Build p50':>12}{'Build p99':>12}{'Verify p50':>12}{'Verify p99':>12}{'Size B':>10}"
    print(hdr)
    print("-" * len(hdr))
    for name, r in results.items():
        if "error" in r:
            print(f"{name:<42}ERROR: {r['error']}")
            continue
        b, v = r["build"], r["verify"]
        print(f"{name:<42}{b['p50_us']:>10.1f}μ {b['p99_us']:>10.1f}μ {v['p50_us']:>10.1f}μ {v['p99_us']:>10.1f}μ {r['size_bytes']:>10}")

    print("""
Sigstore (Fulcio + Rekor) — not measured quantitatively:
  Keyless signing requires a network round-trip to Fulcio (short-lived cert
  issuance via OIDC) and, for the default keyless flow, an inclusion proof
  write to the public Rekor transparency log. Both are network I/O to public
  infra, not local CPU work — a local microbenchmark would show numbers with
  no relationship to real signing latency, so none is reported. Architecturally:
  Sigstore buys a public, third-party-auditable transparency log SPIF does not
  have; SPIF buys per-record signing/verification with zero network dependency
  and no external log to trust or reach. They solve different problems
  (public supply-chain attestation vs. inline per-output provenance) and are
  not really substitutable — the honest comparison is the feature matrix in
  BENCHMARKS.md, not a latency number.
""")


if __name__ == "__main__":
    main()
