/**
 * OpenAI adapter for SPIF — converts OpenAI completions to SPIFDocument.
 *
 * Requires the openai npm package to be installed by the consumer.
 */

import type { SPIFDocument, Node, Distribution, Provenance } from '../types.js';
import { SPIFStreamWriter } from '../streaming.js';
import { SPIFReader } from '../reader.js';
import { DIST_SEM_STABILITY } from '../format.js';

export interface Message {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface OpenAIAdapterOptions {
  model?: string;
  maxTokens?: number;
  logprobs?: boolean;
}

// Derive a Distribution from an array of per-token logprob values
function logprobsToDistribution(logprobs: number[]): Distribution {
  if (logprobs.length === 0) {
    return { mean: 0.8, var: 0.04, shape: 'gaussian', semantics: DIST_SEM_STABILITY };
  }
  // Convert log probs to probs and average
  const probs = logprobs.map(lp => Math.exp(lp));
  const mean = probs.reduce((a, b) => a + b, 0) / probs.length;
  const variance =
    probs.reduce((sum, p) => sum + (p - mean) ** 2, 0) / probs.length;
  return {
    mean: Math.min(1.0, Math.max(0.0, mean)),
    var: variance,
    shape: 'gaussian',
    semantics: DIST_SEM_STABILITY,
  };
}

function buildNode(
  id: string,
  text: string,
  confidence: Distribution,
): Node {
  return {
    id,
    type: 'text',
    value: text,
    confidence,
    refs: [],
  };
}

function buildProvenance(model: string): Provenance {
  return {
    source_model: model,
    model_version: model,
    temperature: 0.0,
    input_hash: '',
    context_ref: '',
    timestamp_ms: Date.now(),
  };
}

function normalizePrompt(prompt: string | Message[]): Message[] {
  if (typeof prompt === 'string') {
    return [{ role: 'user', content: prompt }];
  }
  return prompt;
}

export class OpenAISPIFAdapter {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private client: any;
  private model: string;
  private maxTokens: number;
  private useLogprobs: boolean;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  constructor(client: any, options: OpenAIAdapterOptions = {}) {
    this.client = client;
    this.model = options.model ?? 'gpt-4o-mini';
    this.maxTokens = options.maxTokens ?? 1024;
    this.useLogprobs = options.logprobs ?? false;
  }

  async *stream(
    prompt: string | Message[],
  ): AsyncGenerator<Uint8Array, SPIFDocument> {
    const messages = normalizePrompt(prompt);
    const writer = new SPIFStreamWriter();
    const provenance = buildProvenance(this.model);

    // Emit header
    yield writer.open(provenance);

    const collectedLogprobs: number[] = [];
    let fullText = '';

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const stream = await this.client.chat.completions.create({
      model: this.model,
      messages,
      stream: true,
      max_tokens: this.maxTokens,
      logprobs: this.useLogprobs,
    });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    for await (const chunk of stream as AsyncIterable<any>) {
      const delta = chunk.choices?.[0]?.delta?.content ?? '';
      if (delta) {
        fullText += delta;
        const partial = writer.partialText(delta);
        yield partial;
      }
      // Collect logprobs if available
      if (this.useLogprobs && chunk.choices?.[0]?.logprobs?.content) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        for (const tp of chunk.choices[0].logprobs.content as any[]) {
          if (typeof tp.logprob === 'number') {
            collectedLogprobs.push(tp.logprob);
          }
        }
      }
    }

    const confidence = this.useLogprobs
      ? logprobsToDistribution(collectedLogprobs)
      : { mean: 0.8, var: 0.04, shape: 'gaussian', semantics: DIST_SEM_STABILITY };

    const node = buildNode('main', fullText, confidence);
    const doc: SPIFDocument = {
      payload: [node],
      provenance,
      trace: [],
      trace_method: 'post-hoc',
      alternatives: [],
      signatures: [],
    };

    // Emit tail + checksum
    yield writer.commit(doc);

    // Re-assemble and decode to return as SPIFDocument
    const assembled = concat(writer.open.length > 0 ? new Uint8Array(0) : new Uint8Array(0));
    void assembled;
    return doc;
  }

  async complete(prompt: string | Message[]): Promise<SPIFDocument> {
    const chunks: Uint8Array[] = [];
    let finalDoc: SPIFDocument | null = null;

    const gen = this.stream(prompt);
    let result = await gen.next();
    while (!result.done) {
      chunks.push(result.value as Uint8Array);
      result = await gen.next();
    }
    finalDoc = result.value as SPIFDocument;

    return finalDoc!;
  }
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
