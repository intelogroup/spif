"""SPIF — Semantic Provenance Inference Format v0.2.

Cryptographically signed, tamper-evident provenance for AI outputs.
"""

from .types import (
    Distribution,
    NodeRef,
    Node,
    TraceStep,
    Provenance,
    SemanticLayer,
    Alternative,
    Delta,
    Signature,
    SPIFDocument,
    TaskInfo,
)
from .writer import SPIFWriter, compute_content_id
from .keystore import SPIFKeyStore, verify_with_keystore
from .format import (
    NODE_TEXT, NODE_CODE, NODE_FACT, NODE_CONCEPT, NODE_MULTIMODAL,
    NODE_TOOL_CALL, NODE_TOOL_RESULT,
    DIST_SEM_FACTUAL, DIST_SEM_STABILITY, DIST_SEM_EPISTEMIC, DIST_SEM_TOKEN_PROB,
    KNOWN_DIST_SEMANTICS,
    TOOL_ERROR_PERMISSION, TOOL_ERROR_TIMEOUT, TOOL_ERROR_RATE_LIMIT,
    TOOL_ERROR_VALIDATION, TOOL_ERROR_CONNECTION,
)
from .reader import (
    SPIFReader,
    SPIFError, SPIFMagicError, SPIFVersionError,
    SPIFChecksumError, SPIFSignatureError, SPIFFormatError,
)
from .renderer import SPIFRenderer
from .replay import ReplayGuard, SPIFReplayError
from .exporters.lossless_json import to_lossless_json, from_lossless_json
from .exporters.msgpack import to_msgpack, from_msgpack
from .crypto import (
    derive_key_from_mnemonic,
    load_pem_private_key,
    generate_key,
    export_pem_private_key,
    export_pem_public_key,
)
from .eu_ai_act import DeployerOutput, build_deployer_output
from .governance import (
    EVENT_TYPES,
    EVENT_ROLE_BY_TYPE,
    GovernanceEvent,
    build_event_document,
    event_from_document,
)

__all__ = [
    "Distribution", "NodeRef", "Node", "TraceStep",
    "Provenance", "SemanticLayer", "Alternative", "Delta", "Signature", "SPIFDocument",
    "TaskInfo",
    "SPIFWriter", "SPIFReader", "SPIFRenderer", "compute_content_id",
    "SPIFKeyStore", "verify_with_keystore",
    "SPIFError", "SPIFMagicError", "SPIFVersionError",
    "SPIFChecksumError", "SPIFSignatureError", "SPIFFormatError",
    "ReplayGuard", "SPIFReplayError",
    "NODE_TEXT", "NODE_CODE", "NODE_FACT", "NODE_CONCEPT", "NODE_MULTIMODAL",
    "NODE_TOOL_CALL", "NODE_TOOL_RESULT",
    "DIST_SEM_FACTUAL", "DIST_SEM_STABILITY", "DIST_SEM_EPISTEMIC", "DIST_SEM_TOKEN_PROB",
    "KNOWN_DIST_SEMANTICS",
    "TOOL_ERROR_PERMISSION", "TOOL_ERROR_TIMEOUT", "TOOL_ERROR_RATE_LIMIT",
    "TOOL_ERROR_VALIDATION", "TOOL_ERROR_CONNECTION",
    "to_lossless_json", "from_lossless_json",
    "to_msgpack", "from_msgpack",
    "derive_key_from_mnemonic", "load_pem_private_key",
    "generate_key", "export_pem_private_key", "export_pem_public_key",
    "DeployerOutput", "build_deployer_output",
    "EVENT_TYPES", "EVENT_ROLE_BY_TYPE", "GovernanceEvent",
    "build_event_document", "event_from_document",
]
