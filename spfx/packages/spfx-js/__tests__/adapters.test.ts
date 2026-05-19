/**
 * OpenAI adapter tests — exercises OpenAISPIFAdapter with a mock client.
 * Verifies that the adapter produces well-formed SPIFDocuments that survive roundtrip.
 */

import { describe, test, expect, beforeEach } from '@jest/globals';

import { SPIFReader } from '../src/reader.js';
import { SPIFWriter } from '../src/writer.js';
import { OpenAISPIFAdapter } from '../src/adapters/openai.js';
import type { SPIFDocument } from '../src/types.js';

// ---------------------------------------------------------------------------
// Mock OpenAI client
// ---------------------------------------------------------------------------

// The adapter uses streaming: client.chat.completions.create({stream:true}) must
// return an AsyncIterable of chunk objects.
function makeMockClient(content = 'Paris is the capital of France.') {
  return {
    chat: {
      completions: {
        create: async (_params: unknown) => {
          async function* gen() {
            yield { choices: [{ delta: { content }, finish_reason: null, logprobs: null }] };
            yield { choices: [{ delta: { content: '' }, finish_reason: 'stop', logprobs: null }] };
          }
          return gen();
        },
      },
    },
  };
}

function makeMockClientWithLogprobs() {
  return {
    chat: {
      completions: {
        create: async (_params: unknown) => {
          async function* gen() {
            yield {
              choices: [{
                delta: { content: 'Berlin is the capital of Germany.' },
                finish_reason: null,
                logprobs: { content: [{ logprob: -0.05 }, { logprob: -0.01 }, { logprob: -0.02 }] },
              }],
            };
            yield { choices: [{ delta: { content: '' }, finish_reason: 'stop', logprobs: null }] };
          }
          return gen();
        },
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('OpenAISPIFAdapter', () => {
  let adapter: OpenAISPIFAdapter;

  beforeEach(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    adapter = new OpenAISPIFAdapter(makeMockClient() as any, { model: 'gpt-4o-mini' });
  });


  test('test_adapter_instantiation', () => {
    expect(adapter).toBeDefined();
    expect(adapter).toBeInstanceOf(OpenAISPIFAdapter);
  });

  test('test_complete_returns_spif_document', async () => {
    const doc = await adapter.complete('What is the capital of France?');

    expect(doc).toBeDefined();
    expect(doc.payload).toBeDefined();
    expect(Array.isArray(doc.payload)).toBe(true);
    expect(doc.payload.length).toBeGreaterThan(0);
  });

  test('test_document_payload_has_text_content', async () => {
    const doc = await adapter.complete('What is the capital of France?');
    const node = doc.payload[0];

    expect(typeof node.id).toBe('string');
    expect(typeof node.type).toBe('string');
    expect(node.value).toBeTruthy();
  });

  test('test_document_provenance_populated', async () => {
    const doc = await adapter.complete('What is the capital of France?');

    expect(doc.provenance).toBeDefined();
    expect(typeof doc.provenance!.source_model).toBe('string');
    expect(doc.provenance!.source_model.length).toBeGreaterThan(0);
    expect(doc.provenance!.timestamp_ms).toBeGreaterThan(0);
  });

  test('test_document_confidence_is_valid_distribution', async () => {
    const doc = await adapter.complete('What is the capital of France?');
    const conf = doc.payload[0].confidence;

    expect(conf).toBeDefined();
    expect(conf.mean).toBeGreaterThanOrEqual(0.0);
    expect(conf.mean).toBeLessThanOrEqual(1.0);
    expect(conf.var).toBeGreaterThanOrEqual(0.0);
  });

  test('test_document_survives_encode_decode_roundtrip', async () => {
    const doc = await adapter.complete('What is the capital of France?');

    const writer = new SPIFWriter();
    const reader = new SPIFReader();

    const encoded = writer.encode(doc);
    expect(encoded.length).toBeGreaterThan(0);

    const decoded = reader.decode(encoded);
    expect(decoded.payload.length).toBe(doc.payload.length);
    expect(decoded.payload[0].id).toBe(doc.payload[0].id);
  });

  test('test_string_prompt_and_message_array_produce_equivalent_structure', async () => {
    // Each call needs its own adapter instance since the mock stream is one-shot
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const a1 = new OpenAISPIFAdapter(makeMockClient('A fact.') as any, { model: 'gpt-4o-mini' });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const a2 = new OpenAISPIFAdapter(makeMockClient('A fact.') as any, { model: 'gpt-4o-mini' });

    const doc1 = await a1.complete('Tell me a fact.');
    const doc2 = await a2.complete([{ role: 'user', content: 'Tell me a fact.' }]);

    expect(doc1.payload.length).toBe(doc2.payload.length);
    expect(typeof doc1.payload[0].value).toBe(typeof doc2.payload[0].value);
  });

  test('test_logprobs_adapter_populates_confidence', async () => {
    const logprobsAdapter = new OpenAISPIFAdapter(
      makeMockClientWithLogprobs() as unknown as never,
      { model: 'gpt-4o-mini', logprobs: true },
    );

    const doc = await logprobsAdapter.complete('What is the capital of Germany?');

    expect(doc.payload.length).toBeGreaterThan(0);
    const conf = doc.payload[0].confidence;
    expect(conf.mean).toBeGreaterThanOrEqual(0.0);
    expect(conf.mean).toBeLessThanOrEqual(1.0);
  });

  test('test_encoded_size_is_reasonable', async () => {
    const doc = await adapter.complete('Short question.');
    const encoded = new SPIFWriter().encode(doc);

    // A minimal document should be well under 4KB
    expect(encoded.length).toBeLessThan(4096);
    // But must have content
    expect(encoded.length).toBeGreaterThan(50);
  });
});
