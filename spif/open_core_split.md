# Open-Core Model for SPIF

## Introduction
SPIF will adopt an open-core model to ensure accessibility and adoption, while maintaining a robust commercial moat to protect against proprietary risks. 

## Open Source Components
- **SPEC.md**: This will be published as an open standard, ensuring that the MIME `application/x-spif` and the `.spif` magic bytes remain intact.
- **Core Library & CLI**: The essential functionality, including commands such as `spif validate`, `spif inspect`, and `spif verify`, will be open-sourced under Apache-2.0.
- **Reference Wrappers**: Open-source wrappers for LLM calls (OpenAI, Anthropic, LangChain, Vercel AI SDK, LlamaIndex) encouraging widespread use and adoption.

## Commercial Components
- **Hosted Transparency Log / Registry**: A commercial service that enables enterprises to maintain a tamper-evident, searchable log of all SPIF documents uploaded, ensuring trust and integrity in the validation process.
- **Enterprise Control Plane**: Advanced features for key management (HSM/KMS), compliance mapping, and custom reporting for sectors like HR, healthcare, and finance, which will drive additional revenue.
- **Compliance Pack**: Pre-built artifacts tailored for specific industries, offering critical support in audits and compliance checks.

## Conclusion
By framing SPIF with an open-core approach, we position it not only as a tool for compliance but as a fundamental layer of trust for enterprise users looking to navigate the complexities of AI regulation and provenance.