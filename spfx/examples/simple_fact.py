"""Example: minimal SIF document — a single fact node."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from spfx import SPIFDocument, Node, Distribution, SPIFWriter, SPIFReader, SPIFRenderer

doc = SPIFDocument(payload=[
    Node(
        id="capital",
        type="fact",
        value="Paris is the capital of France.",
        confidence=Distribution(mean=0.99, var=0.001, shape="gaussian"),
    )
])

data = SPIFWriter().encode(doc)
print(f"Encoded: {len(data)} bytes")
print(f"Magic:   {data[:8].hex()}")

restored = SPIFReader().decode(data)
print(SPIFRenderer().render(restored))
