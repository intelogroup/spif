"""
LlamaIndex + SPIF — wrap any LlamaIndex LLM or query engine with tamper-evident provenance.

Two patterns:

1. **LLM wrapper**: wrap any LlamaIndex LLM (OpenAI, Anthropic, etc.) so every
   complete() call also produces a SPIFDocument.

2. **Query engine wrapper**: wrap a full RAG query engine — captures the response,
   source nodes, and provenance in a SPIF document.

Run:
    pip install spfx llama-index llama-index-llms-openai
    OPENAI_API_KEY=sk-... python examples/llamaindex_adapter.py

Or:
    pip install spfx llama-index llama-index-llms-anthropic
    ANTHROPIC_API_KEY=sk-ant-... python examples/llamaindex_adapter.py --provider anthropic
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from typing import Any

from spif import SPIFDocument, SPIFWriter
from spif.types import Node, Provenance


class SPIFLLMWrapper:
    """
    Wraps any LlamaIndex LLM so every complete() also returns a SPIFDocument.

    Usage:
        from llama_index.llms.openai import OpenAI
        llm = SPIFLLMWrapper(OpenAI(model="gpt-4o-mini"))
        response, doc = llm.complete("What is SPIF?")
    """

    def __init__(self, llm: Any, sign_key: Any = None, signer_id: str | None = None) -> None:
        self._llm = llm
        self._writer = SPIFWriter(sign_key=sign_key, signer_id=signer_id)

    def complete(self, prompt: str) -> tuple[Any, SPIFDocument]:
        input_hash = hashlib.sha256(prompt.encode()).digest()
        ts = int(time.time() * 1000)

        response = self._llm.complete(prompt)

        source_model = getattr(self._llm, "model", None) or "unknown"
        text = str(response)

        doc = SPIFDocument(
            payload=[Node(id="0", type="text", value=text)],
            provenance=Provenance(
                source_model=source_model,
                timestamp_ms=ts,
                input_hash=input_hash,
            ),
        )

        return response, doc

    async def acomplete(self, prompt: str) -> tuple[Any, SPIFDocument]:
        input_hash = hashlib.sha256(prompt.encode()).digest()
        ts = int(time.time() * 1000)

        response = await self._llm.acomplete(prompt)

        source_model = getattr(self._llm, "model", None) or "unknown"
        doc = SPIFDocument(
            payload=[Node(id="0", type="text", value=str(response))],
            provenance=Provenance(
                source_model=source_model,
                timestamp_ms=ts,
                input_hash=input_hash,
            ),
        )

        return response, doc


class SPIFQueryEngineWrapper:
    """
    Wraps a LlamaIndex query engine so each query() returns a SPIFDocument
    that includes both the answer and the source node references.

    Usage:
        index = VectorStoreIndex.from_documents(docs)
        engine = SPIFQueryEngineWrapper(index.as_query_engine())
        response, doc = engine.query("What is the main finding?")
    """

    def __init__(self, query_engine: Any, model_name: str = "unknown") -> None:
        self._engine = query_engine
        self._model_name = model_name

    def query(self, question: str) -> tuple[Any, SPIFDocument]:
        input_hash = hashlib.sha256(question.encode()).digest()
        ts = int(time.time() * 1000)

        response = self._engine.query(question)

        nodes: list[Node] = [
            Node(id="answer", type="text", value=str(response))
        ]

        # Attach source nodes as fact nodes so auditors can see what was retrieved
        source_nodes = getattr(response, "source_nodes", [])
        for i, src in enumerate(source_nodes):
            text = getattr(src, "text", None) or getattr(getattr(src, "node", None), "text", "")
            score = getattr(src, "score", None)
            nodes.append(Node(
                id=f"source_{i}",
                type="fact",
                value=text[:500],  # cap at 500 chars per source node
                metadata={"score": score} if score is not None else {},
            ))

        doc = SPIFDocument(
            payload=nodes,
            provenance=Provenance(
                source_model=self._model_name,
                timestamp_ms=ts,
                input_hash=input_hash,
            ),
        )

        return response, doc


def demo_llm_wrapper(provider: str) -> None:
    if provider == "anthropic":
        try:
            from llama_index.llms.anthropic import Anthropic
        except ImportError:
            sys.exit("llama-index-llms-anthropic not installed. Run: pip install llama-index-llms-anthropic")
        llm = SPIFLLMWrapper(Anthropic(model="claude-haiku-4-5-20251001"))
    else:
        try:
            from llama_index.llms.openai import OpenAI
        except ImportError:
            sys.exit("llama-index-llms-openai not installed. Run: pip install llama-index-llms-openai")
        llm = SPIFLLMWrapper(OpenAI(model="gpt-4o-mini"))

    print(f"[{provider}] Calling LLM via SPIFLLMWrapper...")
    response, doc = llm.complete(
        "Explain what makes a binary file format trustworthy in one sentence."
    )

    print(f"\nResponse: {response}")
    print(f"\nSPIF provenance:")
    print(f"  model:      {doc.provenance.source_model}")
    print(f"  timestamp:  {doc.provenance.timestamp_ms}")
    print(f"  nodes:      {len(doc.payload)}")

    SPIFWriter().write(doc, "/tmp/llamaindex_llm.spfx")
    print("Saved to /tmp/llamaindex_llm.spfx")
    print("Verify with: spfx validate /tmp/llamaindex_llm.spfx")


def demo_rag_wrapper(provider: str) -> None:
    """Pattern 2: RAG query engine — captures answer + source nodes."""
    try:
        from llama_index.core import VectorStoreIndex, Document
    except ImportError:
        sys.exit("llama-index not installed. Run: pip install llama-index llama-index-llms-openai")

    if provider == "anthropic":
        try:
            from llama_index.llms.anthropic import Anthropic
            from llama_index.core import Settings
            Settings.llm = Anthropic(model="claude-haiku-4-5-20251001")
        except ImportError:
            sys.exit("llama-index-llms-anthropic not installed.")
    else:
        try:
            from llama_index.llms.openai import OpenAI
            from llama_index.core import Settings
            Settings.llm = OpenAI(model="gpt-4o-mini")
        except ImportError:
            sys.exit("llama-index-llms-openai not installed.")

    docs = [
        Document(text=(
            "SPIF is a binary wire format that wraps AI outputs with SHA-256 checksums "
            "and optional ed25519 signatures. Every byte change is detected on decode. "
            "It supports content-addressed audit chains via context_ref."
        )),
        Document(text=(
            "The SPIF wire format uses CBOR encoding with chunk framing similar to PNG. "
            "The checksum chunk covers all preceding bytes including the signature chunk, "
            "so removing the signature is also detected."
        )),
    ]

    print(f"\n[{provider}] Building RAG index and querying via SPIFQueryEngineWrapper...")
    index = VectorStoreIndex.from_documents(docs)
    engine = SPIFQueryEngineWrapper(
        index.as_query_engine(),
        model_name=provider,
    )

    response, doc = engine.query("How does SPIF detect tampering?")

    print(f"\nAnswer: {response}")
    print(f"\nSPIF document: {len(doc.payload)} nodes (answer + {len(doc.payload)-1} sources)")

    SPIFWriter().write(doc, "/tmp/llamaindex_rag.spfx")
    print("Saved to /tmp/llamaindex_rag.spfx")
    print("Verify with: spfx inspect /tmp/llamaindex_rag.spfx")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=["openai", "anthropic"], default="openai")
    parser.add_argument("--skip-rag", action="store_true", help="Skip the RAG demo (requires embedding model)")
    args = parser.parse_args()

    demo_llm_wrapper(args.provider)

    if not args.skip_rag:
        demo_rag_wrapper(args.provider)
