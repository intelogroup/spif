/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const spif_document_free: (a: number) => void;
export const spif_document_get_confidence_mean: (a: number) => number;
export const spif_document_get_confidence_var: (a: number) => number;
export const spif_document_get_model_id: (a: number) => number;
export const spif_document_get_model_version: (a: number) => number;
export const spif_document_get_prompt_hash: (a: number) => number;
export const spif_document_get_signer: (a: number) => number;
export const spif_document_get_tool_call_error: (a: number, b: number) => number;
export const spif_document_get_tool_call_latency: (a: number, b: number) => number;
export const spif_document_get_tool_call_name: (a: number, b: number) => number;
export const spif_document_get_tool_count: (a: number) => number;
export const spif_document_get_verification_status: (a: number) => number;
export const spif_document_parse: (a: number, b: number) => number;
export const spif_document_parse_strict: (a: number, b: number) => number;
export const verify: (a: number, b: number) => [number, number, number, number];
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_start: () => void;
