"""SPIF command-line interface."""

from __future__ import annotations
import base64
import struct
from pathlib import Path

import typer

from .reader import SPIFReader, SPIFError
from .renderer import SPIFRenderer
from .format import CHUNK_NAMES

app = typer.Typer(name="spif", help="Semantic Provenance Inference Format tools — v0.2", add_completion=False)


@app.command()
def render(path: Path = typer.Argument(..., help="Path to a .spif file")):
    """Render a SPIF file as human-readable text."""
    typer.echo(
        "WARNING: spif render is for human debugging only. "
        "Confidence bars are visual — do not parse them programmatically. "
        "For model consumption use: spif export --lossless-json",
        err=True,
    )
    try:
        doc = SPIFReader().read(path)
    except SPIFError as e:
        typer.echo(f"ERROR: {e}", err=True)
        raise typer.Exit(1)
    typer.echo(SPIFRenderer().render(doc))


@app.command()
def export(
    path: Path = typer.Argument(..., help="Path to a .spif file"),
    lossless_json: bool = typer.Option(False, "--lossless-json", help="Export as lossless JSON for model consumption (~440 tokens vs ~1350 for base64)"),
    msgpack_export: bool = typer.Option(False, "--msgpack", help="Export as lossless MsgPack bytes"),
    output: Path = typer.Option(None, "--output", "-o", help="Write to file instead of stdout"),
    indent: int = typer.Option(None, "--indent", help="Pretty-print indent level"),
):
    """Export a SPIF file as lossless JSON or MsgPack."""
    selected = int(lossless_json) + int(msgpack_export)
    if selected != 1:
        typer.echo("Specify exactly one export format. Available: --lossless-json, --msgpack", err=True)
        raise typer.Exit(1)

    try:
        doc = SPIFReader().read(path)
    except SPIFError as e:
        typer.echo(f"ERROR: {e}", err=True)
        raise typer.Exit(1)

    if lossless_json:
        from .exporters.lossless_json import to_lossless_json
        result = to_lossless_json(doc, indent=indent)

        if output:
            output.write_text(result, encoding="utf-8")
            typer.echo(f"Exported {path} -> {output}")
        else:
            typer.echo(result)
    else:
        from .exporters.msgpack import to_msgpack
        result = to_msgpack(doc)

        if output:
            output.write_bytes(result)
            typer.echo(f"Exported {path} -> {output}")
        else:
            import sys
            sys.stdout.buffer.write(result)


@app.command()
def validate(
    path: Path = typer.Argument(..., help="Path to a .spif file"),
    strict: bool = typer.Option(False, "--strict", help="Reject unsigned documents"),
):
    """Validate a SPIF file (magic, version, checksum, DAG, schema)."""
    try:
        reader = SPIFReader.strict() if strict else SPIFReader()
        reader.read(path)
        typer.echo(f"OK  {path}")
    except SPIFError as e:
        typer.echo(f"FAIL  {path}: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def inspect(
    path: Path = typer.Argument(..., help="Path to a .spif file"),
    layer: str = typer.Option("all", help="Layer: all | payload | trace | provenance | semantic | alts | signature"),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON (EU AI Act Art. 50 fields)"),
):
    """Show a specific layer of a SPIF file."""
    try:
        doc = SPIFReader().read(path)
    except SPIFError as e:
        typer.echo(f"ERROR: {e}", err=True)
        raise typer.Exit(1)

    if json_output:
        import json as _json
        p = doc.provenance
        typer.echo(_json.dumps({
            "producer": p.source_model if p else None,
            "model_version": p.model_version if p else None,
            "timestamp_ms": p.timestamp_ms if p else None,
            "human_oversight": p.human_oversight if p else None,
            "risk_tier": p.risk_tier if p else None,
            "model_card": p.model_card if p else None,
            "training_data_hash": p.training_data_hash if p else None,
            "energy_wh": p.energy_wh if p else None,
            "signed": doc.signature is not None,
            "signer": doc.signature.signer if doc.signature else None,
        }, indent=2))
        return

    if layer == "all":
        size = path.stat().st_size
        typer.echo(f"Content-Type: application/x-spif")
        typer.echo(f"File: {path}  ({size} bytes)")

    if layer in ("all", "payload"):
        typer.echo(f"PAYLOAD ({len(doc.payload)} nodes)")
        from .renderer import _render_node
        for n in doc.payload:
            typer.echo(_render_node(n))
    if layer in ("all", "trace") and doc.trace:
        typer.echo(f"\nTRACE ({len(doc.trace)} steps, method={doc.trace_method})")
        depth: dict[str, int] = {}
        for st in doc.trace:
            depth[st.id] = 0 if not st.deps else max(depth.get(d, 0) for d in st.deps) + 1
        from .renderer import _render_step
        for st in doc.trace:
            typer.echo(_render_step(st, indent=depth.get(st.id, 0)))
    if layer in ("all", "provenance") and doc.provenance:
        p = doc.provenance
        typer.echo(
            f"\nPROVENANCE\n"
            f"  model={p.source_model}  temp={p.temperature}  "
            f"hash={p.input_hash[:16] if p.input_hash else 'n/a'}"
        )
    if layer in ("all", "semantic") and doc.semantic:
        typer.echo(f"\nSEMANTIC  model={doc.semantic.embedding_model or 'unspecified'}  dim={doc.semantic.dim}")
    if layer in ("all", "alts") and doc.alternatives:
        typer.echo(f"\nALTERNATIVES  count={len(doc.alternatives)}")
    if layer in ("all", "signature"):
        if doc.signature:
            typer.echo(
                f"\nSIGNATURE\n"
                f"  algorithm: {doc.signature.algorithm}\n"
                f"  signer:    {doc.signature.signer}\n"
                f"  bytes:     {doc.signature.signature.hex()[:32]}..."
            )
        else:
            typer.echo("\nSIGNATURE  none")


@app.command()
def hexdump(path: Path = typer.Argument(..., help="Path to a .spif file")):
    """Show the raw chunk structure of a SPIF file."""
    data = path.read_bytes()
    typer.echo(f"magic:   {data[:9].hex()}")
    typer.echo(f"version: {data[9]:02x}")
    typer.echo(f"flags:   {data[10]:08b}")
    offset = 11
    while offset < len(data):
        if offset + 5 > len(data):
            break
        chunk_type, length = struct.unpack_from(">BI", data, offset)
        name = CHUNK_NAMES.get(chunk_type, f"0x{chunk_type:02x}")
        typer.echo(f"chunk:   {name:<12} offset={offset:6d}  length={length}")
        offset += 5 + length


@app.command()
def sign(
    path: Path = typer.Argument(..., help="Path to a .spif file to sign"),
    key: Path = typer.Option(..., help="Path to ed25519 private key file (PEM or raw 32-byte seed)"),
    output: Path = typer.Option(None, help="Output path (default: overwrite input)"),
    signer_id: str = typer.Option("local", help="Signer identifier (URL or name)"),
):
    """Sign a SPIF file with an ed25519 private key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, Encoding, PublicFormat,
    )
    from .types import Signature
    from .writer import SPIFWriter

    # Load private key
    key_bytes = key.read_bytes()
    try:
        if key_bytes.startswith(b"-----"):
            private_key = load_pem_private_key(key_bytes, password=None)
        else:
            # Raw 32-byte seed
            private_key = Ed25519PrivateKey.from_private_bytes(key_bytes[:32])
    except Exception as e:
        typer.echo(f"ERROR loading key: {e}", err=True)
        raise typer.Exit(1)

    # Read existing document
    try:
        doc = SPIFReader().read(path)
    except SPIFError as e:
        typer.echo(f"ERROR reading file: {e}", err=True)
        raise typer.Exit(1)

    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_bytes).decode()
    final_signer = signer_id if signer_id != "local" else pub_b64

    writer = SPIFWriter()

    # Pass 1: dummy 64-byte sig to lock in final body structure (header flags etc.)
    doc.signature = Signature(algorithm="ed25519", signer=final_signer, signature=b"\x00" * 64)
    dummy = writer.encode(doc)

    # Find SIGNATURE chunk offset in dummy encoding
    from .format import MAGIC as _MAGIC
    offset = len(_MAGIC) + 2
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == 0x07:  # CHUNK_SIGNATURE
            sig_offset = offset
            break
        if ct == 0xFF:
            break
        offset += 5 + ln

    if sig_offset is None:
        typer.echo("ERROR: could not locate SIGNATURE chunk in encoded document", err=True)
        raise typer.Exit(1)

    body_to_sign = dummy[:sig_offset]

    # Pass 2: real signature, re-encode
    raw_sig = private_key.sign(body_to_sign)
    doc.signature = Signature(
        algorithm="ed25519",
        signer=final_signer,
        signature=raw_sig,
    )
    out_path = output or path
    writer.write(doc, out_path)
    typer.echo(f"Signed  {out_path}  (signer: {doc.signature.signer[:32]}{'...' if len(doc.signature.signer) > 32 else ''})")


@app.command()
def verify(
    path: Path = typer.Argument(..., help="Path to a signed .spif file"),
    pubkey: str = typer.Option(None, help="Base64 ed25519 public key (overrides signer field)"),
):
    """Verify the ed25519 signature in a SPIF file."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    data = path.read_bytes()
    try:
        doc = SPIFReader().decode(data)
    except SPIFError as e:
        typer.echo(f"ERROR: {e}", err=True)
        raise typer.Exit(1)

    if doc.signature is None:
        typer.echo("UNSIGNED  no signature chunk present")
        raise typer.Exit(2)

    # Find body_to_sign
    from .format import MAGIC as _MAGIC
    offset = len(_MAGIC) + 2
    sig_chunk_offset = None
    while offset < len(data):
        if offset + 5 > len(data):
            break
        chunk_type, length = struct.unpack_from(">BI", data, offset)
        if chunk_type == 0x07:  # CHUNK_SIGNATURE
            sig_chunk_offset = offset
            break
        if chunk_type == 0xFF:  # CHUNK_CHECKSUM
            break
        offset += 5 + length

    if sig_chunk_offset is None:
        typer.echo("UNSIGNED  signature chunk not found in body")
        raise typer.Exit(2)

    body_to_sign = data[:sig_chunk_offset]
    key_b64 = pubkey or doc.signature.signer

    try:
        pub_bytes = base64.b64decode(key_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(doc.signature.signature, body_to_sign)
        typer.echo(f"VALID  {path}  (signer: {doc.signature.signer[:40]})")
    except InvalidSignature:
        typer.echo(f"INVALID  signature verification failed for {path}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"ERROR  {e}", err=True)
        raise typer.Exit(1)


@app.command()
def sidecar(
    port: int = typer.Option(8000, "--port", "-p", help="Port to run the sidecar HTTP server on"),
    upstream: str = typer.Option(None, "--upstream", "-u", help="Optional upstream LLM provider URL for reverse proxy mode"),
    policy: Path = typer.Option(None, "--policy", help="Path to JSON policy file"),
    keystore: Path = typer.Option(None, "--keystore", help="Path to SPIFKeyStore directory"),
    crl_url: str = typer.Option(None, "--crl-url", help="Optional URL to fetch CRL from (overrides policy crl_check.endpoint)"),
):
    """Start the SPIF policy enforcement and key revocation HTTP sidecar."""
    import logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    from .sidecar import start_sidecar
    typer.echo(f"Starting SPIF Sidecar on port {port}...")
    try:
        start_sidecar(
            port=port,
            upstream_url=upstream,
            policy_path=policy,
            keystore_dir=keystore,
            crl_url=crl_url,
        )
    except Exception as e:
        typer.echo(f"ERROR: {e}", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
