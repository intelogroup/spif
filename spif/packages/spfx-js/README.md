# spif-js

**TypeScript/Node.js implementation of SPIF — cryptographically signed, tamper-evident provenance for AI outputs.**

```
npm install spif-js
```

Requires Node.js 18+.

---

## What it does

SPIF wraps any AI model response in a binary container with:
- SHA-256 checksum (detects any byte change on decode)
- Optional ed25519 signature (proves who produced it)
- Provenance metadata (model, timestamp, input hash, chain reference)

Any byte changed after writing raises `SPIFChecksumError` or `SPIFSignatureError` on read. No silent corruptions.

---

## Quickstart

### Read a SPIF file

```typescript
import { SPIFReader } from 'spif-js';
import { readFileSync } from 'fs';

const bytes = new Uint8Array(readFileSync('response.spif'));
const doc = new SPIFReader().decode(bytes);

console.log(doc.provenance?.sourceModel);   // "gpt-4o"
console.log(doc.provenance?.timestampMs);   // Unix epoch ms
console.log(doc.payload[0].value);          // response text
```

### Write a SPIF document

```typescript
import { SPIFWriter } from 'spif-js';
import { writeFileSync } from 'fs';

const writer = new SPIFWriter();
const doc = {
  payload: [{ id: '1', type: 'text', value: 'Hello world' }],
  provenance: {
    sourceModel: 'gpt-4o',
    timestampMs: Date.now(),
    inputHash: new Uint8Array(32),
  },
};

const bytes = writer.encode(doc);
writeFileSync('response.spif', bytes);
```

### OpenAI adapter

```typescript
import OpenAI from 'openai';
import { OpenAISPIFAdapter } from 'spif-js';
import { writeFileSync } from 'fs';

const client = new OpenAI();
const adapter = new OpenAISPIFAdapter(client, { model: 'gpt-4o' });

const doc = await adapter.complete([
  { role: 'user', content: 'Summarize the EU AI Act.' }
]);

writeFileSync('response.spif', new SPIFWriter().encode(doc));
```

### Streaming

```typescript
import { SPIFStreamWriter, SPIFStreamReader } from 'spif-js';

const writer = new SPIFStreamWriter({ model: 'gpt-4o' });

// Write chunks as they arrive from the model
writer.writeTextChunk('Hello ');
writer.writeTextChunk('world');
const bytes = writer.finalize();

// Read them back
const reader = new SPIFStreamReader();
for (const event of reader.readAll(bytes)) {
  if (event.type === 'text_chunk') process.stdout.write(event.text);
}
```

### Verify on decode

```typescript
const reader = new SPIFReader({ requireSignature: true });
// Throws SPIFChecksumError if any byte changed
// Throws SPIFSignatureError if signature missing or invalid
const doc = reader.decode(bytes);
```

---

## Error types

| Error | Cause |
|-------|-------|
| `SPIFMagicError` | Not a SPIF file |
| `SPIFVersionError` | Unsupported format version |
| `SPIFChecksumError` | File corrupted or tampered |
| `SPIFSignatureError` | Signature missing or invalid |
| `SPIFFormatError` | Malformed chunk structure |

---

## Python interop

`spif-js` is wire-compatible with the Python `spif` package. Documents written by Python can be read by Node.js and vice versa. The cross-implementation compat test suite verifies this on every CI run.

```bash
pip install spif     # Python writer
npm install spif-js  # Node.js reader
```

---

## License

Apache-2.0
