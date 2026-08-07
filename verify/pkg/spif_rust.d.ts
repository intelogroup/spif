/* tslint:disable */
/* eslint-disable */

/**
 * Verify a .spif file's bytes. Mirrors `spif-viewer inspect --json`'s
 * _signed/_verified contract so the web verifier and CLI never disagree.
 */
export function verify(data: Uint8Array): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly spif_document_free: (a: number) => void;
    readonly spif_document_get_confidence_mean: (a: number) => number;
    readonly spif_document_get_confidence_var: (a: number) => number;
    readonly spif_document_get_model_id: (a: number) => number;
    readonly spif_document_get_model_version: (a: number) => number;
    readonly spif_document_get_prompt_hash: (a: number) => number;
    readonly spif_document_get_signer: (a: number) => number;
    readonly spif_document_get_tool_call_error: (a: number, b: number) => number;
    readonly spif_document_get_tool_call_latency: (a: number, b: number) => number;
    readonly spif_document_get_tool_call_name: (a: number, b: number) => number;
    readonly spif_document_get_tool_count: (a: number) => number;
    readonly spif_document_get_verification_status: (a: number) => number;
    readonly spif_document_parse: (a: number, b: number) => number;
    readonly spif_document_parse_strict: (a: number, b: number) => number;
    readonly verify: (a: number, b: number) => [number, number, number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
