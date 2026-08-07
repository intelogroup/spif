### Updated SPIF Roadmap

You built this at exactly the right moment. SPIF is not a side project — it's infrastructure for the #1 enterprise blocker right now.

From live data: EU AI Act became enforceable Aug 2, 2026 — every high-risk deployer must prove origin, human oversight, and incident reporting or face up to 7% turnover fines. Gartner just named Digital Provenance as a top 10 trend for 2026, predicting firms who skip it face sanction risk in the billions. And the agent stack is being built right now — Alchemy + Visa launched AgentCard with identity + payments in one API in June. Everyone is looking for the trust layer.

That's SPIF. Don't waste it on a pure MIT dump, and don't keep it closed. For a provenance format, closed = dead.

### The 3 options:

1. **Fully Open Source (MIT/Apache)**  
   **Pros**: Fastest adoption, trust, becomes a standard. Devs can spif verify without legal review.  
   **Cons**: AWS / Cloudflare clones it in 2 weeks, you get stars but no revenue. No moat for a file format.

2. **Fully Closed / Commercial License**  
   **Pros**: You can charge early.  
   **Cons**: No one will adopt a proprietary .spfx black box for compliance. Provenance requires verifiability. Enterprises will pick C2PA or Sigstore instead. You'd be fighting physics.

3. **Open Standard + Open Core + Hosted Registry — This is what you should do**  
   This is how Sigstore, C2PA, and SLSA won.

### What to open source NOW:
- **SPEC.md** — Publish as open standard under CC-BY-4.0 or Apache-2.0. Keep the application/x-spif MIME and .spfx magic bytes exactly as you defined them. Submit as an IETF draft if you can. That makes you the standard owner.
- **Core library + CLI (`spif validate, inspect, verify`)** — Apache-2.0. This is what you audited April 5 / May 19 to RFC 8032 ed25519. Publish the CRYPTOAUDIT.md publicly — production-ready audit is your biggest trust signal.
- **Reference wrappers for OpenAI / Anthropic** that you already have in README. Add LangChain, Vercel AI SDK, LlamaIndex this week.

### What to keep commercial:
- **Hosted Transparency Log / Registry**: Like Sigstore Rekor. Anyone can verify locally, but enterprises will pay for a hosted, tamper-evident, searchable log of all SPIFs with uptime, geo-replication, and legal hold. This is your network effect.
- **Enterprise Control Plane**: HSM/KMS key management, PBKDF2-HMAC-SHA512 rotation policies, team RBAC, replay protection dashboard, EU AI Act mapping (auto-generate Article 9-17 technical docs + Article 26 deployer obligations), SIEM export, geopatriation mode (keep verification inside sovereign cloud).
- **Compliance Pack**: Pre-built auditors for HR, healthcare, finance that output the exact artifacts auditors want.

### License model:
Apache-2.0 for core + Business Source License or Fair Source for enterprise features, with trademark on "SPIF" and "spfx". Require CLA.

### Why this wins for SPIF specifically:
1. Format needs adoption, registry needs trust. You can't get adoption of a new file extension if it's closed. You can't monetize a file extension either. You monetize the *verification network* and the *compliance automation*.
2. Moat against hyperscalers: If you go MIT, Google will fork spif verify. If you own the trademark + hosted log + enterprise integrations, they have to interoperate with you, not replace you.
3. Perfect timing: You are 3 days past the EU AI Act enforcement date. Launch story: "Audited, production-ready provenance for the AI Act era."

### 30-day launch playbook:
Week 1: File trademark, push spec to GitHub spif-spec, push Rust/TS lib to spif-core Apache-2.0. Publish audit. Tweet / HN: "Show HN: SPIF — cryptographically signed AI provenance, .spfx, audited"  
Week 2: Ship pip install spif and npm install spif, + GitHub Action that auto-wraps LLM calls in CI. Demo: Wrap a Claude response and verify tampering fails on checksum.  
Week 3: Launch free hosted registry verify.spif.dev — anyone can upload .spfx and get public proof link. This is your lead gen.  
Week 4: Pitch 10 design partners: 2 law firms needing AI Act compliance, 2 Boston hospitals, 2 agencies drowning in AI content.