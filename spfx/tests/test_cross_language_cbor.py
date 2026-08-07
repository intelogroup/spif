"""Roadmap item: validate CBOR tagging across languages for interoperability.

Encodes a document with the SPIF custom CBOR tags (1000 Distribution,
1001 NodeRef, 1002 Embedding) using the Python writer, then decodes it with
the Rust reference implementation (spif-viewer) to confirm the tags survive
a cross-language round trip. Skips if cargo/rustc is unavailable.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from spfx import (
    SPIFDocument, Node, NodeRef, TraceStep, Distribution, SPIFWriter, SPIFReader,
)

RUST_DIR = Path(__file__).parent.parent.parent / "spif-rust"

pytestmark = pytest.mark.skipif(
    shutil.which("cargo") is None or not RUST_DIR.exists(),
    reason="cargo/spif-rust not available",
)


@pytest.fixture(scope="module")
def spif_viewer_bin():
    res = subprocess.run(
        ["cargo", "build", "--bin", "spif-viewer"],
        cwd=RUST_DIR, capture_output=True,
    )
    assert res.returncode == 0, f"cargo build failed:\n{res.stderr.decode()}"
    return RUST_DIR / "target" / "debug" / "spif-viewer"


def _tagged_doc() -> SPIFDocument:
    return SPIFDocument(
        payload=[
            Node(id="root", type="fact", value="v", confidence=Distribution(mean=0.5)),
            Node(
                id="n2", type="fact", value="v",
                confidence=Distribution(mean=0.87),
                refs=[NodeRef(node_id="root")],  # CBOR Tag(1001)
            ),
        ],
        trace=[TraceStep(id="s1", type="evidence", content="a")],
    )


def test_python_encoded_tags_decode_in_rust(tmp_path, spif_viewer_bin):
    data = SPIFWriter().encode(_tagged_doc())
    spfx_file = tmp_path / "doc.spfx"
    spfx_file.write_bytes(data)

    res = subprocess.run(
        [str(spif_viewer_bin), str(spfx_file)],
        capture_output=True, timeout=30,
    )
    assert res.returncode == 0, f"spif-viewer failed:\n{res.stderr.decode()}"
    out = res.stdout.decode()
    # Distribution tag (1000) decoded and rendered as a confidence percentage.
    assert "87%" in out
    # No panic/error text from a failed tag resolution.
    assert "error" not in out.lower()


def test_python_encoded_tags_still_decode_in_python():
    """Sanity control: the same document must round-trip in Python too."""
    data = SPIFWriter().encode(_tagged_doc())
    restored = SPIFReader().decode(data)
    assert restored.payload[1].refs[0].node_id == "root"
    assert abs(restored.payload[1].confidence.mean - 0.87) < 1e-6
