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
 * @brief Opaque handle representing a parsed and verified SPIF Document.
 */
typedef struct spif_document spif_document_t;

/**
 * @brief Parse a raw SPIF CBOR binary payload in standard/lenient mode.
 *
 * This validates the CBOR structure and reads all contained fields.
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
 * @param document Pointer to the spif_document_t.
 * @return "valid" if signature verified, or "untrusted" if unsigned/unverified.
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
