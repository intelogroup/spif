"""
LangChain + SPIF — wrap any LangChain LLM call with tamper-evident provenance.

This example shows two patterns:

1. **Drop-in wrapper**: pass any LangChain BaseChatModel through SPIFChatModel
   and every invoke() call returns a SPIF-wrapped response automatically.

2. **Manual**: call your LangChain chain normally, then wrap the result in SPIF
   yourself using SPIFWriter.

Run:
    pip install spif langchain langchain-openai
    OPENAI_API_KEY=sk-... python examples/langchain_adapter.py

Or with Anthropic:
    pip install spif langchain langchain-anthropic
    ANTHROPIC_API_KEY=sk-ant-... python examples/langchain_adapter.py --provider anthropic
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from typing import Any

try:
    from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.outputs import ChatGeneration, ChatResult
except ImportError:
    sys.exit("langchain-core not installed. Run: pip install langchain langchain-openai")

from spif import SPIFDocument, SPIFWriter
from spif.types import Node, Provenance


class SPIFChatModel:
    """
    Thin wrapper around any LangChain BaseChatModel.

    Every call to invoke() returns both the normal LangChain AIMessage
    and a SPIFDocument with checksum-verified provenance.

    Usage:
        from langchain_openai import ChatOpenAI
        model = SPIFChatModel(ChatOpenAI(model="gpt-4o"))
        response, doc = model.invoke("Summarize the EU AI Act.")
    """

    def __init__(
        self,
        llm: BaseChatModel,
        signer_id: str | None = None,
        sign_key: Any | None = None,
    ) -> None:
        self._llm = llm
        self._signer_id = signer_id
        self._sign_key = sign_key
        self._writer = SPIFWriter(sign_key=sign_key, signer_id=signer_id)

    def invoke(self, prompt: str | list[BaseMessage]) -> tuple[AIMessage, SPIFDocument]:
        if isinstance(prompt, str):
            messages = [HumanMessage(content=prompt)]
            input_text = prompt
        else:
            messages = prompt
            input_text = " ".join(
                m.content for m in messages if hasattr(m, "content") and isinstance(m.content, str)
            )

        # Record the input hash before calling the model
        input_hash = hashlib.sha256(input_text.encode()).digest()
        ts = int(time.time() * 1000)

        response: AIMessage = self._llm.invoke(messages)

        # Extract model name — LangChain stores it in response_metadata
        source_model = (
            getattr(response, "response_metadata", {}).get("model_name")
            or getattr(self._llm, "model_name", None)
            or "unknown"
        )

        text = response.content if isinstance(response.content, str) else str(response.content)

        doc = SPIFDocument(
            payload=[Node(id="0", type="text", value=text)],
            provenance=Provenance(
                source_model=source_model,
                timestamp_ms=ts,
                input_hash=input_hash,
            ),
        )

        return response, doc

    def invoke_and_save(self, prompt: str, path: str) -> AIMessage:
        """Convenience: invoke, write SPIF to path, return the AIMessage."""
        response, doc = self.invoke(prompt)
        self._writer.write(doc, path)
        return response


def demo_drop_in(provider: str) -> None:
    if provider == "anthropic":
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError:
            sys.exit("langchain-anthropic not installed. Run: pip install langchain-anthropic")
        llm = ChatAnthropic(model="claude-haiku-4-5-20251001")
    else:
        try:
            from langchain_openai import ChatOpenAI
        except ImportError:
            sys.exit("langchain-openai not installed. Run: pip install langchain-openai")
        llm = ChatOpenAI(model="gpt-4o-mini")

    model = SPIFChatModel(llm)

    print(f"[{provider}] Calling model via SPIFChatModel...")
    response, doc = model.invoke("Explain what makes a binary file format trustworthy in one sentence.")

    print(f"\nResponse: {response.content}")
    print(f"\nSPIF provenance:")
    print(f"  model:       {doc.provenance.source_model}")
    print(f"  timestamp:   {doc.provenance.timestamp_ms}")
    print(f"  input_hash:  {doc.provenance.input_hash.hex()[:16]}...")

    # Write to disk — tamper-evident
    writer = SPIFWriter()
    writer.write(doc, "/tmp/langchain_response.spif")
    print(f"\nSaved to /tmp/langchain_response.spif")
    print("Verify with: spif validate /tmp/langchain_response.spif")


def demo_manual_wrap(provider: str) -> None:
    """Pattern 2: call LangChain normally, wrap result manually."""
    if provider == "anthropic":
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError:
            sys.exit("langchain-anthropic not installed.")
        llm = ChatAnthropic(model="claude-haiku-4-5-20251001")
    else:
        try:
            from langchain_openai import ChatOpenAI
        except ImportError:
            sys.exit("langchain-openai not installed.")
        llm = ChatOpenAI(model="gpt-4o-mini")

    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import StrOutputParser

    chain = ChatPromptTemplate.from_messages([
        ("system", "You are a concise technical assistant."),
        ("human", "{question}"),
    ]) | llm | StrOutputParser()

    question = "What is the purpose of a SHA-256 checksum?"
    input_hash = hashlib.sha256(question.encode()).digest()
    ts = int(time.time() * 1000)

    print(f"\n[{provider}] Calling chain manually...")
    text = chain.invoke({"question": question})

    doc = SPIFDocument(
        payload=[Node(id="0", type="text", value=text)],
        provenance=Provenance(
            source_model=getattr(llm, "model_name", "unknown"),
            timestamp_ms=ts,
            input_hash=input_hash,
        ),
    )

    SPIFWriter().write(doc, "/tmp/langchain_chain_response.spif")
    print(f"Response: {text[:100]}...")
    print("Saved to /tmp/langchain_chain_response.spif")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=["openai", "anthropic"], default="openai")
    args = parser.parse_args()

    demo_drop_in(args.provider)
    demo_manual_wrap(args.provider)
