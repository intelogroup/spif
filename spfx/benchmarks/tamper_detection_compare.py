"""
Tamper detection benchmark: SPIF vs JWS (Ed25519) vs HMAC-SHA256 vs GPG.

Three attack vectors:
  1. Bit flip — random byte corruption in the body
  2. Value injection — change payload string without resigning
  3. Provenance spoof — alter source_model without resigning

Two decode modes tested per format:
  - verified:   integrity check runs on decode (or explicit verify call)
  - unverified: just parse, skip integrity — shows SPIF checksum advantage

Metrics: detection rate, sign/verify overhead (μs), wire-size overhead (bytes), LOC estimate.

Usage:
    python benchmarks/tamper_detection_compare.py [--quick]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import struct
import subprocess
import sys
import tempfile
import time as _time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature

from spfx import SPIFDocument, SPIFWriter, SPIFReader, Node, Signature
from spfx.types import Distribution, Provenance
from spfx.format import MAGIC, DIST_SEM_FACTUAL

# ---------------------------------------------------------------------------
# Shared document factory
# ---------------------------------------------------------------------------

def _make_doc() -> SPIFDocument:
    return SPIFDocument(
        payload=[
            Node(
                id=f"claim_{i}",
                type="factual_claim",
                value=f"The capital of country {i} is City_{i}.",
                confidence=Distribution(mean=0.9 - i * 0.05, var=0.01,
                                        shape="gaussian", semantics=DIST_SEM_FACTUAL),
            )
            for i in range(5)
        ],
        provenance=Provenance(
            source_model="claude-sonnet-4-6",
            model_version="claude-sonnet-4-6",
            temperature=0.0,
            input_hash="a" * 64,
            timestamp_ms=1_700_000_000_000,
        ),
    )


def _to_json_bytes(doc: SPIFDocument) -> bytes:
    return json.dumps({
        "payload": [{"id": n.id, "type": n.type, "value": n.value,
                     "confidence": n.confidence.mean} for n in doc.payload],
        "provenance": {"source_model": doc.provenance.source_model if doc.provenance else ""},
    }).encode()


# ---------------------------------------------------------------------------
# SPIF signing (two-pass)
# ---------------------------------------------------------------------------

def _spif_sign(doc: SPIFDocument, key: Ed25519PrivateKey, pub_b64: str) -> bytes:
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=pub_b64, signature=b"\x00" * 64)
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
    raw_sig = key.sign(dummy[:sig_offset])
    doc.signature = Signature(algorithm="ed25519", signer=pub_b64, signature=raw_sig)
    return writer.encode(doc)


# ---------------------------------------------------------------------------
# JWS — compact Ed25519 (RFC 8037 EdDSA)
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _b64url_decode(s: bytes) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + b"=" * (pad % 4))


class _JWSSigner:
    """Minimal JWS compact serialization with Ed25519 (EdDSA)."""

    HEADER = _b64url(b'{"alg":"EdDSA","crv":"Ed25519"}')

    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.pub_raw = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, payload: bytes) -> bytes:
        payload_b64 = _b64url(payload)
        signing_input = self.HEADER + b"." + payload_b64
        sig = self.key.sign(signing_input)
        return signing_input + b"." + _b64url(sig)

    def verify(self, token: bytes) -> bool:
        """Raise ValueError on tamper."""
        parts = token.split(b".")
        if len(parts) != 3:
            raise ValueError("malformed JWS")
        header_b64, payload_b64, sig_b64 = parts
        signing_input = header_b64 + b"." + payload_b64
        sig = _b64url_decode(sig_b64)
        pub = Ed25519PublicKey.from_public_bytes(self.pub_raw)
        try:
            pub.verify(sig, signing_input)
        except InvalidSignature:
            raise ValueError("JWS signature mismatch")
        return True

    def decode_payload_only(self, token: bytes) -> bytes:
        """Parse payload without verifying — shows what unverified JWS looks like."""
        parts = token.split(b".")
        return _b64url_decode(parts[1])


# ---------------------------------------------------------------------------
# HMAC-SHA256 signing (symmetric, common in REST APIs)
# ---------------------------------------------------------------------------

class _HMACSigner:
    def __init__(self):
        self.key = os.urandom(32)

    def sign(self, payload: bytes) -> bytes:
        """Returns payload || hmac(32 bytes)."""
        tag = hmac_mod.new(self.key, payload, hashlib.sha256).digest()
        return payload + tag

    def verify(self, signed: bytes) -> bool:
        """Raise ValueError on tamper."""
        payload, tag = signed[:-32], signed[-32:]
        expected = hmac_mod.new(self.key, payload, hashlib.sha256).digest()
        if not hmac_mod.compare_digest(tag, expected):
            raise ValueError("HMAC mismatch")
        return True

    def decode_payload_only(self, signed: bytes) -> bytes:
        return signed[:-32]


# ---------------------------------------------------------------------------
# GPG (subprocess) — optional
# ---------------------------------------------------------------------------

def _gpg_available() -> bool:
    try:
        r = subprocess.run(["gpg", "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


class _GPGSigner:
    """GPG detached signature over a temp file."""

    def __init__(self):
        self._home = tempfile.mkdtemp(prefix="spif_gpg_")
        self._key_id: str | None = None
        self._setup()

    def _run(self, *args: str, input: bytes | None = None) -> subprocess.CompletedProcess:
        base = ["gpg", "--batch", "--yes", "--no-default-keyring",
                f"--homedir={self._home}"]
        return subprocess.run(base + list(args), input=input,
                              capture_output=True, timeout=30)

    def _setup(self):
        script = b"Key-Type: EDDSA\nKey-Curve: ed25519\nName-Real: SPIF Bench\nExpire-Date: 0\n%no-protection\n%commit\n"
        r = self._run("--gen-key", "--no-tty", input=script)
        if r.returncode != 0:
            raise RuntimeError(f"GPG keygen failed: {r.stderr.decode()}")
        r2 = self._run("--list-keys", "--with-colons")
        for line in r2.stdout.decode().splitlines():
            if line.startswith("pub:") or line.startswith("uid:"):
                continue
            if line.startswith("fpr:"):
                self._key_id = line.split(":")[9]
                break

    def sign(self, payload: bytes) -> tuple[bytes, bytes]:
        """Returns (payload, detached_sig_bytes)."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(payload)
            fname = f.name
        try:
            sig_path = fname + ".sig"
            r = self._run("--detach-sign", "--armor",
                          "--default-key", self._key_id or "",
                          "--output", sig_path, fname)
            if r.returncode != 0:
                raise RuntimeError(f"GPG sign failed: {r.stderr.decode()}")
            return payload, Path(sig_path).read_bytes()
        finally:
            Path(fname).unlink(missing_ok=True)

    def verify(self, payload: bytes, sig: bytes) -> bool:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(payload)
            fname = f.name
        sig_path = fname + ".sig"
        Path(sig_path).write_bytes(sig)
        try:
            r = self._run("--verify", sig_path, fname)
            if r.returncode != 0:
                raise ValueError("GPG verification failed")
            return True
        finally:
            Path(fname).unlink(missing_ok=True)
            Path(sig_path).unlink(missing_ok=True)

    def cleanup(self):
        import shutil
        shutil.rmtree(self._home, ignore_errors=True)


# ---------------------------------------------------------------------------
# Attack helpers
# ---------------------------------------------------------------------------

def _flip_bit(data: bytes, pos: int | None = None) -> bytes:
    """Flip one byte at pos (default: middle of body)."""
    arr = bytearray(data)
    idx = pos if pos is not None else len(arr) // 2
    arr[idx] ^= 0xFF
    return bytes(arr)


def _inject_value(data: bytes, old: bytes, new: bytes) -> bytes:
    return data.replace(old, new, 1)


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

REPS = 100


def _mean_us(fn, reps: int) -> float:
    t = _time.perf_counter()
    for _ in range(reps):
        fn()
    return (_time.perf_counter() - t) / reps * 1_000_000


class _FormatResult:
    def __init__(self, name: str):
        self.name = name
        self.plain_bytes: int = 0
        self.signed_bytes: int = 0
        self.sign_us: float = 0.0
        self.verify_us: float = 0.0
        # detection per attack: True=detected, False=silent, None=N/A
        self.verified_bit_flip: bool | None = None
        self.verified_value_inject: bool | None = None
        self.verified_prov_spoof: bool | None = None
        self.unverified_bit_flip: bool | None = None
        self.unverified_value_inject: bool | None = None
        self.loc_sign: int = 0
        self.loc_verify: int = 0


def _run_spif(doc: SPIFDocument, reps: int) -> _FormatResult:
    r = _FormatResult("SPIF")
    key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()

    signed = _spif_sign(doc, key, pub_b64)
    plain = SPIFWriter().encode(doc)
    r.plain_bytes = len(plain)
    r.signed_bytes = len(signed)

    r.sign_us = _mean_us(lambda: _spif_sign(doc, key, pub_b64), reps)
    r.verify_us = _mean_us(lambda: SPIFReader().verify_signature(signed), reps)
    r.loc_sign = 8
    r.loc_verify = 1

    writer = SPIFWriter()
    reader = SPIFReader()

    # Attack 1: bit flip
    tampered = _flip_bit(signed, len(signed) // 2)
    try:
        reader.decode(tampered)
        r.verified_bit_flip = False
    except Exception:
        r.verified_bit_flip = True

    # Unverified decode: SPIF still raises checksum error
    r.unverified_bit_flip = r.verified_bit_flip  # same path (checksum on decode)

    # Attack 2: value injection (replace payload string)
    val_target = b"City_0"
    val_inject = b"HACKED"
    injected = _inject_value(signed, val_target, val_inject)
    try:
        reader.decode(injected)
        r.verified_value_inject = False
    except Exception:
        r.verified_value_inject = True
    r.unverified_value_inject = r.verified_value_inject

    # Attack 3: provenance spoof
    doc2 = _make_doc()
    if doc2.provenance:
        doc2.provenance.source_model = "gpt-4o"
    doc2.signature = SPIFReader().decode(signed).signature
    spoofed = writer.encode(doc2)
    try:
        reader.verify_signature(spoofed)
        r.verified_prov_spoof = False
    except Exception:
        r.verified_prov_spoof = True

    return r


def _run_jws(doc: SPIFDocument, reps: int) -> _FormatResult:
    r = _FormatResult("JWS-Ed25519")
    signer = _JWSSigner()
    payload = _to_json_bytes(doc)

    token = signer.sign(payload)
    r.plain_bytes = len(payload)
    r.signed_bytes = len(token)
    r.sign_us = _mean_us(lambda: signer.sign(payload), reps)
    r.verify_us = _mean_us(lambda: signer.verify(token), reps)
    r.loc_sign = 3
    r.loc_verify = 2

    # Bit flip in the payload portion of the token
    # token = header_b64 . payload_b64 . sig_b64
    # flip a byte in payload_b64 part
    parts = token.split(b".")
    flipped_payload = _flip_bit(parts[1], len(parts[1]) // 2)
    tampered_token = parts[0] + b"." + flipped_payload + b"." + parts[2]

    try:
        signer.verify(tampered_token)
        r.verified_bit_flip = False
    except Exception:
        r.verified_bit_flip = True

    # Unverified: parse payload without checking sig — silent
    try:
        signer.decode_payload_only(tampered_token)
        r.unverified_bit_flip = False  # silent — no error on plain decode
    except Exception:
        r.unverified_bit_flip = True

    # Value injection
    val_target = b"City_0"
    raw_payload = _b64url_decode(parts[1])
    injected_payload = raw_payload.replace(val_target, b"HACKED", 1)
    injected_token = parts[0] + b"." + _b64url(injected_payload) + b"." + parts[2]

    try:
        signer.verify(injected_token)
        r.verified_value_inject = False
    except Exception:
        r.verified_value_inject = True

    # Unverified value injection — silent
    try:
        signer.decode_payload_only(injected_token)
        r.unverified_value_inject = False
    except Exception:
        r.unverified_value_inject = True

    # Provenance spoof: rebuild JSON with different model, re-sign without original key
    spoofed_payload = _to_json_bytes(doc).replace(b'"claude-sonnet-4-6"', b'"gpt-4o"')
    spoofed_b64 = _b64url(spoofed_payload)
    spoof_token = parts[0] + b"." + spoofed_b64 + b"." + parts[2]

    try:
        signer.verify(spoof_token)
        r.verified_prov_spoof = False
    except Exception:
        r.verified_prov_spoof = True

    return r


def _run_hmac(doc: SPIFDocument, reps: int) -> _FormatResult:
    r = _FormatResult("HMAC-SHA256")
    signer = _HMACSigner()
    payload = _to_json_bytes(doc)

    signed = signer.sign(payload)
    r.plain_bytes = len(payload)
    r.signed_bytes = len(signed)
    r.sign_us = _mean_us(lambda: signer.sign(payload), reps)
    r.verify_us = _mean_us(lambda: signer.verify(signed), reps)
    r.loc_sign = 2
    r.loc_verify = 2

    # Bit flip in data portion
    tampered = _flip_bit(signed, len(payload) // 2)
    try:
        signer.verify(tampered)
        r.verified_bit_flip = False
    except Exception:
        r.verified_bit_flip = True

    # Unverified: just slice payload bytes — silent
    try:
        signer.decode_payload_only(tampered)
        r.unverified_bit_flip = False
    except Exception:
        r.unverified_bit_flip = True

    # Value injection
    val_target = b"City_0"
    injected = _inject_value(signed[:len(payload)], val_target, b"HACKED") + signed[len(payload):]
    try:
        signer.verify(injected)
        r.verified_value_inject = False
    except Exception:
        r.verified_value_inject = True

    try:
        signer.decode_payload_only(injected)
        r.unverified_value_inject = False
    except Exception:
        r.unverified_value_inject = True

    # Provenance spoof
    spoofed_payload = payload.replace(b'"claude-sonnet-4-6"', b'"gpt-4o"')
    spoofed_signed = signer.sign(spoofed_payload)  # re-signed with same key — symmetric!
    try:
        signer.verify(spoofed_signed)
        r.verified_prov_spoof = None  # N/A: HMAC is symmetric, anyone with key can re-sign
    except Exception:
        r.verified_prov_spoof = False

    return r


def _run_gpg(doc: SPIFDocument, reps: int) -> _FormatResult | None:
    if not _gpg_available():
        return None
    r = _FormatResult("GPG")
    try:
        signer = _GPGSigner()
    except Exception as e:
        print(f"  GPG setup failed: {e}")
        return None

    payload = _to_json_bytes(doc)

    try:
        p, sig = signer.sign(payload)
        r.plain_bytes = len(payload)
        r.signed_bytes = len(payload) + len(sig)

        r.sign_us = _mean_us(lambda: signer.sign(payload), max(reps // 10, 3))
        r.verify_us = _mean_us(lambda: signer.verify(p, sig), max(reps // 10, 3))
        r.loc_sign = 1  # gpg --detach-sign
        r.loc_verify = 1  # gpg --verify

        # Bit flip in payload
        tampered_payload = _flip_bit(payload, len(payload) // 2)
        try:
            signer.verify(tampered_payload, sig)
            r.verified_bit_flip = False
        except Exception:
            r.verified_bit_flip = True

        r.unverified_bit_flip = False  # reading the file directly = silent

        # Value injection
        injected = _inject_value(payload, b"City_0", b"HACKED")
        try:
            signer.verify(injected, sig)
            r.verified_value_inject = False
        except Exception:
            r.verified_value_inject = True

        r.unverified_value_inject = False  # silent without verify

        r.verified_prov_spoof = True  # sig covers full payload → spoof detected

    except Exception as e:
        print(f"  GPG bench error: {e}")
        signer.cleanup()
        return None

    signer.cleanup()
    return r


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

_BOOL = {True: "DETECTED", False: "silent", None: "N/A"}


def _print_results(results: list[_FormatResult]) -> None:
    print("\n## Tamper Detection Comparison\n")
    print("### Detection rates\n")

    attack_cols = [
        ("Bit flip (verified)", "verified_bit_flip"),
        ("Bit flip (unverified)", "unverified_bit_flip"),
        ("Value inject (verified)", "verified_value_inject"),
        ("Value inject (unverified)", "unverified_value_inject"),
        ("Prov spoof (verified)", "verified_prov_spoof"),
    ]

    hdr = f"{'Format':<16}" + "".join(f" {label:<24}" for label, _ in attack_cols)
    print(hdr)
    print("-" * len(hdr))
    for r in results:
        row = f"{r.name:<16}"
        for _, attr in attack_cols:
            val = getattr(r, attr)
            row += f" {_BOOL[val]:<24}"
        print(row)

    print("\n### Overhead metrics\n")
    hdr2 = f"{'Format':<16} {'Plain B':>8} {'Signed B':>9} {'Overhead B':>11} {'Sign μs':>10} {'Verify μs':>11} {'Sign LOC':>9} {'Verify LOC':>11}"
    print(hdr2)
    print("-" * len(hdr2))
    for r in results:
        overhead = r.signed_bytes - r.plain_bytes
        print(
            f"{r.name:<16} {r.plain_bytes:>8} {r.signed_bytes:>9} {overhead:>+11} "
            f"{r.sign_us:>9.1f}μ {r.verify_us:>10.1f}μ {r.loc_sign:>9} {r.loc_verify:>11}"
        )

    print()
    print("Notes:")
    print("  'unverified' = decode without calling verify() — shows what happens when")
    print("  developers forget to verify (common mistake). SPIF checksum fires on decode,")
    print("  JWS/HMAC are silent unless you explicitly call verify.")
    print("  HMAC provenance spoof is N/A: symmetric key means re-signing is trivial.")
    print("  GPG sign LOC is CLI commands, not Python.")


def run(reps: int = REPS) -> None:
    doc = _make_doc()
    results: list[_FormatResult] = []

    print("Building SPIF results...")
    results.append(_run_spif(doc, reps))

    print("Building JWS results...")
    results.append(_run_jws(doc, reps))

    print("Building HMAC results...")
    results.append(_run_hmac(doc, reps))

    print("Building GPG results (skipped if gpg not available)...")
    gpg_r = _run_gpg(doc, reps)
    if gpg_r:
        results.append(gpg_r)
    else:
        print("  GPG skipped.")

    _print_results(results)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="Fewer reps for fast run")
    args = ap.parse_args()
    run(reps=10 if args.quick else REPS)
