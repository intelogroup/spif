#include <stdio.h>
#include <stdlib.h>
#include "../include/spif.h"

int main() {
    // 1. Read the valid sample spif file
    const char* filepath = "../../examples/fixtures/sample_valid.spif";
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        // Fallback for running from parent directory or other contexts
        filepath = "../../examples/fixtures/sample_valid.spif";
        file = fopen(filepath, "rb");
    }
    
    if (!file) {
        fprintf(stderr, "Error: Could not open examples/fixtures/sample_valid.spif\n");
        return 1;
    }
    
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    unsigned char* buffer = (unsigned char*)malloc(size);
    if (!buffer) {
        fprintf(stderr, "Error: Out of memory reading file\n");
        fclose(file);
        return 1;
    }
    
    if (fread(buffer, 1, size, file) != size) {
        fprintf(stderr, "Error: Could not read full file contents\n");
        free(buffer);
        fclose(file);
        return 1;
    }
    fclose(file);
    
    printf("[C Connector] Successfully loaded %ld bytes from %s\n", size, filepath);
    
    // 2. Parse and verify using C Connector API
    printf("[C Connector] Parsing and verifying signature...\n");
    spif_document_t* doc = spif_document_parse(buffer, size);
    if (!doc) {
        fprintf(stderr, "Error: Failed to parse SPIF document!\n");
        free(buffer);
        return 1;
    }
    
    // 3. Extract and display values
    const char* status = spif_document_get_verification_status(doc);
    const char* signer = spif_document_get_signer(doc);
    const char* model_id = spif_document_get_model_id(doc);
    const char* model_version = spif_document_get_model_version(doc);
    const char* prompt_hash = spif_document_get_prompt_hash(doc);
    double confidence_mean = spif_document_get_confidence_mean(doc);
    double confidence_var = spif_document_get_confidence_var(doc);
    int tool_count = spif_document_get_tool_count(doc);
    
    printf("\n--- SPIF Document Metadata (C FFI) ---\n");
    printf("Verification Status: %s\n", status);
    printf("Signer Public Key  : %s\n", signer);
    printf("Model ID           : %s\n", model_id);
    printf("Model Version      : %s\n", model_version);
    printf("Prompt Hash        : %s\n", prompt_hash);
    printf("Confidence Mean    : %f\n", confidence_mean);
    printf("Confidence Variance: %f\n", confidence_var);
    printf("Tool Count         : %d\n", tool_count);
    
    for (int i = 0; i < tool_count; i++) {
        const char* name = spif_document_get_tool_call_name(doc, i);
        bool is_error = spif_document_get_tool_call_error(doc, i);
        double latency = spif_document_get_tool_call_latency(doc, i);
        printf("  * Tool[%d]: %s (failed=%s, latency=%.1fms)\n", 
               i, name, is_error ? "true" : "false", latency);
    }
    printf("--------------------------------------\n\n");
    
    // 4. Free allocated document
    printf("[C Connector] Freeing document...\n");
    spif_document_free(doc);
    free(buffer);
    
    printf("[C Connector] Verification test completed successfully!\n");
    return 0;
}
