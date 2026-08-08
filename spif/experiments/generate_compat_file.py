import os
import sys
from pathlib import Path

# Add local sif to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sif import SIFDocument, Node, Distribution, Provenance, TraceStep, SIFWriter, SemanticLayer, Alternative, NodeRef

def generate_complex_test_file(output_path):
    """Generate a complex SIF file in Python to be read by Rust."""
    print(f"Generating complex SIF file at {output_path}...")
    
    # 1. Payload with diverse distributions and refs
    nodes = [
        Node(
            id="node_1",
            type="observation",
            value="The sky is blue.",
            confidence=Distribution(mean=0.99, var=0.001, shape="gaussian", semantics="factual")
        ),
        Node(
            id="node_2",
            type="inference",
            value="It is daytime.",
            confidence=Distribution(mean=0.95, var=0.02, shape="gaussian", semantics="logical"),
            refs=[NodeRef("node_1")]
        )
    ]
    
    # 2. Trace with a DAG structure
    trace = [
        TraceStep(
            id="step_1",
            type="retrieval",
            content="Looked up weather data.",
            confidence=Distribution(mean=1.0, var=0.0, shape="gaussian", semantics="epistemic"),
            deps=[]
        ),
        TraceStep(
            id="step_2",
            type="reasoning",
            content="If weather data shows clear sky, then sky is blue.",
            confidence=Distribution(mean=0.9, var=0.05, shape="gaussian", semantics="epistemic"),
            deps=["step_1"]
        )
    ]
    
    # 3. Full metadata
    doc = SIFDocument(
        payload=nodes,
        trace=trace,
        trace_method="chain-of-thought",
        provenance=Provenance(
            source_model="python-tester-v1",
            model_version="1.0.0",
            timestamp_ms=1712000000000,
            temperature=0.7,
            input_hash="f" * 64,
            context_ref="ctx_001"
        ),
        semantic=SemanticLayer(
            embedding=[0.1, 0.2, 0.3, 0.4] * 32, # 128-dim
            embedding_model="text-embedding-3-small"
        ),
        alternatives=[
            Alternative(
                weight=1.0,
                nodes=[Node(id="alt_1", type="thought", value="Maybe it's green?", confidence=Distribution.certain())],
                normalized=True
            )
        ]
    )
    
    SIFWriter().write(doc, output_path)
    print("Done.")

if __name__ == "__main__":
    out = Path(__file__).parent.parent / "python_generated.sif"
    generate_complex_test_file(out)
