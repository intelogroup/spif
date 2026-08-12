"""Example: SIF document showcasing uncertainty and semantic layer."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from spif import (
    SPIFDocument, Node, NodeRef, Distribution,
    SemanticLayer, Alternative, SPIFWriter, SPIFReader, SPIFRenderer,
)

# A genuinely uncertain claim — with bimodal distribution
doc = SPIFDocument(
    payload=[
        Node(
            id="claim",
            type="fact",
            value="The economic impact of remote work on urban office real estate is negative.",
            confidence=Distribution(mean=0.58, var=0.12, shape="bimodal", p5=0.2, p95=0.85),
        ),
        Node(
            id="caveat",
            type="concept",
            value="Uncertainty is high due to conflicting post-2023 data from different metro areas.",
            confidence=Distribution(mean=0.95, var=0.01, shape="gaussian"),
            refs=[NodeRef("claim")],
        ),
    ],
    semantic=SemanticLayer(
        embedding=[0.312, -0.087, 0.541, 0.209, -0.433, 0.178, 0.801, -0.312],
        covariance=[
            [0.04, 0.01],
            [0.01, 0.03],
        ],
    ),
    alternatives=[
        Alternative(weight=0.42, nodes=[
            Node(id="alt1", type="fact",
                 value="Remote work has mixed/neutral long-term effects on office real estate.",
                 confidence=Distribution(mean=0.42, var=0.15, shape="uniform")),
        ]),
    ]
)

data = SPIFWriter().encode(doc)
print(f"Encoded: {len(data)} bytes  (with semantic layer + alternatives)")
restored = SPIFReader().decode(data)
print(SPIFRenderer().render(restored))
