/**
 * @file spif.h
 * @brief Semantic Provenance Inference Format (SPIF) C Connector / FFI bindings.
 *
 * This header defines the C API for parsing, verifying, and querying SPIF 
 * document metadata, optimized for low-latency integrations into security agents 
 * (e.g. CrowdStrike Falcon) and firewalls (e.g. Palo Alto PAN-OS).
 */

#ifndef SPIF_H
#define SPIF_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque handle representing a parsed SPIF Document.
 *
 * A handle returned by spif_document_parse() is NOT necessarily verified —
 * check spif_document_get_verification_status() before trusting its contents
 * for any security-relevant decision. Only spif_document_parse_strict()
 * guarantees the returned handle carries a verified signature.
 */
typedef struct spif_document spif_document_t;

/**
 * @brief Parse a raw SPIF CBOR binary payload in standard/lenient mode.
 *
 * This validates the CBOR structure, reads all contained fields, and — if a
 * SIGNATURE/MULTISIG chunk is present — attempts to cryptographically verify
 * it, exposing the real outcome via spif_document_get_verification_status().
 * Unlike spif_document_parse_strict(), a missing or invalid signature does
 * NOT cause this function to fail; it returns the document with status
 * "unsigned" or "invalid" so callers can inspect untrusted content
 * deliberately. Security-sensitive callers MUST check
 * spif_document_get_verification_status() before trusting the result, or use
 * spif_document_parse_strict() instead.
 *
 * @param data Pointer to the start of the binary payload buffer.
 * @param size The size of the payload buffer in bytes.
 * @return A pointer to a spif_document_t on success, or NULL on parsing failure.
 *         Must be deallocated using spif_document_free().
 */
spif_document_t* spif_document_parse(const unsigned char* data, size_t size);

/**
 * @brief Parse a raw SPIF CBOR binary payload in strict mode.
 *
 * Strict mode requires that the document has a valid, untampered signature chunk.
 * If the signature is missing or verification fails, this function returns NULL.
 *
 * @param data Pointer to the start of the binary payload buffer.
 * @param size The size of the payload buffer in bytes.
 * @return A pointer to a spif_document_t on success, or NULL on verification/parsing failure.
 *         Must be deallocated using spif_document_free().
 */
spif_document_t* spif_document_parse_strict(const unsigned char* data, size_t size);

/**
 * @brief Deallocate the SPIF document handle and release all associated memory.
 *
 * @param document Pointer to the spif_document_t to free.
 */
void spif_document_free(spif_document_t* document);

/**
 * @brief Get the cryptographic verification status of the document.
 *
 * This reflects an actual signature verification outcome, not merely whether
 * a SIGNATURE/MULTISIG chunk is present in the bytes.
 *
 * @param document Pointer to the spif_document_t.
 * @return "valid" if a present signature cryptographically verified,
 *         "unsigned" if the document carries no signature chunk, or
 *         "invalid" if a signature chunk is present but failed verification
 *         (malformed key/signature bytes or a verification mismatch).
 *         A handle from spif_document_parse_strict() is always "valid".
 *         Memory is owned by the document and remains valid until spif_document_free is called.
 */
const char* spif_document_get_verification_status(const spif_document_t* document);

/**
 * @brief Get the comma-separated signer public keys/identities.
 *
 * @param document Pointer to the spif_document_t.
 * @return The signer string or empty string if unsigned.
 *         Memory is owned by the document and remains valid until spif_document_free is called.
 */
const char* spif_document_get_signer(const spif_document_t* document);

/**
 * @brief Get the source model identifier.
 *
 * @param document Pointer to the spif_document_t.
 * @return The model identifier string.
 *         Memory is owned by the document and remains valid until spif_document_free is called.
 */
const char* spif_document_get_model_id(const spif_document_t* document);

/**
 * @brief Get the version or revision identifier of the model.
 *
 * @param document Pointer to the spif_document_t.
 * @return The model version string.
 *         Memory is owned by the document and remains valid until spif_document_free is called.
 */
const char* spif_document_get_model_version(const spif_document_t* document);

/**
 * @brief Get the SHA-256 hash of the generating input prompt.
 *
 * @param document Pointer to the spif_document_t.
 * @return The prompt hash hex string.
 *         Memory is owned by the document and remains valid until spif_document_free is called.
 */
const char* spif_document_get_prompt_hash(const spif_document_t* document);

/**
 * @brief Get the aggregated average confidence of all output assertions in the document payload.
 *
 * @param document Pointer to the spif_document_t.
 * @return A double in the range [0.0, 1.0].
 */
double spif_document_get_confidence_mean(const spif_document_t* document);

/**
 * @brief Get the aggregated variance of output assertions in the document payload.
 *
 * @param document Pointer to the spif_document_t.
 * @return A double >= 0.0 representing variance.
 */
double spif_document_get_confidence_var(const spif_document_t* document);

/**
 * @brief Get the total number of tool calls recorded in the document payload.
 *
 * @param document Pointer to the spif_document_t.
 * @return The count of tool calls.
 */
int spif_document_get_tool_count(const spif_document_t* document);

/**
 * @brief Get the tool name at a specific index.
 *
 * @param document Pointer to the spif_document_t.
 * @param index The 0-based index of the tool call (must be less than spif_document_get_tool_count).
 * @return The function/tool name string, or NULL if index is out of bounds.
 *         Memory is owned by the document and remains valid until spif_document_free is called.
 */
const char* spif_document_get_tool_call_name(const spif_document_t* document, int index);

/**
 * @brief Check if the tool call at a specific index failed or returned an error.
 *
 * @param document Pointer to the spif_document_t.
 * @param index The 0-based index of the tool call.
 * @return true if the tool execution failed, false otherwise.
 */
bool spif_document_get_tool_call_error(const spif_document_t* document, int index);

/**
 * @brief Get the latency of the tool call at a specific index.
 *
 * @param document Pointer to the spif_document_t.
 * @param index The 0-based index of the tool call.
 * @return The latency in milliseconds.
 */
double spif_document_get_tool_call_latency(const spif_document_t* document, int index);

#ifdef __cplusplus
}
#endif

#endif /* SPIF_H */
