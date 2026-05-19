"""Example: SIF document with full reasoning trace DAG."""

import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from spfx import (
    SPIFDocument, Node, TraceStep,
    Distribution, Provenance, SPIFWriter, SPIFReader, SPIFRenderer,
)

doc = SPIFDocument(
    payload=[
        Node(id="conclusion", type="fact",
             value="Photosynthesis converts CO2 and water into glucose using light energy.",
             confidence=Distribution(mean=0.98, var=0.005, shape="gaussian")),
    ],
    provenance=Provenance(
        source_model="claude-sonnet-4-6",
        model_version="4.6",
        temperature=0.3,
        input_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        timestamp_ms=int(time.time() * 1000),
    ),
    trace=[
        TraceStep(
            id="s1", type="evidence",
            content="Input asks about the mechanism of photosynthesis",
            confidence=Distribution(mean=1.0, var=0.0, shape="point"),
        ),
        TraceStep(
            id="s2", type="hypothesis",
            content="Photosynthesis is a light-driven chemical reaction",
            confidence=Distribution(mean=0.97, var=0.01, shape="gaussian"),
            deps=["s1"],
            alternatives=["Photosynthesis is purely thermal", "Photosynthesis uses ATP directly"],
        ),
        TraceStep(
            id="s3", type="inference",
            content="Reactants: CO2 + H2O + light → C6H12O6 + O2",
            confidence=Distribution(mean=0.99, var=0.002, shape="gaussian", p5=0.97, p95=1.0),
            deps=["s2"],
        ),
        TraceStep(
            id="s4", type="conclusion",
            content="Photosynthesis converts CO2 and water into glucose using light energy.",
            confidence=Distribution(mean=0.98, var=0.005, shape="gaussian"),
            deps=["s3"],
        ),
    ]
)

data = SPIFWriter().encode(doc)
print(f"Encoded: {len(data)} bytes  (with full trace)")
restored = SPIFReader().decode(data)
print(SPIFRenderer().render(restored))
