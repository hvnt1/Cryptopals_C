// Detect AES in ECB mode
// In this file are a bunch of hex-encoded ciphertexts.

// One of them has been encrypted with ECB.

// Detect it.

// Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BLOCK_SIZE 16  // AES block size in bytes

// Function to convert a hex string to a byte array
void hex_to_bytes(const char *hex, unsigned char *out) {
    size_t len = strlen(hex);
    for (size_t i = 0; i < len / 2; i++) {
        sscanf(hex + 2 * i, "%2hhx", &out[i]);
    }
}

// Function to check if there are duplicate 16-byte blocks
int has_duplicate_blocks(unsigned char *ciphertext, size_t len) {
    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        for (size_t j = i + BLOCK_SIZE; j < len; j += BLOCK_SIZE) {
            if (memcmp(ciphertext + i, ciphertext + j, BLOCK_SIZE) == 0) {
                return 1;  // Duplicate block found
            }
        }
    }
    return 0;  // No duplicates found
}

// Function to read the entire file into a buffer
char *read_file(const char *filename, size_t *buffer_size) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Could not open file");
        return NULL;
    }

    // Move to the end to find the file size
    fseek(file, 0, SEEK_END);
    *buffer_size = ftell(file);
    rewind(file);

    // Allocate buffer for file contents
    char *buffer = (char *)malloc(*buffer_size + 1);  // +1 for null terminator
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return NULL;
    }

    // Read the file into the buffer and null-terminate
    fread(buffer, 1, *buffer_size, file);
    buffer[*buffer_size] = '\0';
    fclose(file);

    return buffer;
}

int main() {
    size_t buffer_size;
    char* contents = read_file("1.8.txt", &buffer_size);
    char* ciphertexts[210];
    char *token = strtok(contents, "\n");

    int line_count = 0;
    while (token != NULL) {
        if (line_count < 210) {
            ciphertexts[line_count] = token;
            line_count++;
        }
        token = strtok(NULL, "\n");
    }

    size_t num_ciphertexts = sizeof(ciphertexts) / sizeof(ciphertexts[0]);

    for (size_t i = 0; i < num_ciphertexts; i++) {
        size_t len = strlen(ciphertexts[i]) / 2;
        unsigned char *ciphertext = malloc(len);

        // Convert hex string to byte array
        hex_to_bytes(ciphertexts[i], ciphertext);

        // Check for duplicate blocks
        if (has_duplicate_blocks(ciphertext, len)) {
            printf("Line %zu is encrypted using AES in ECB mode.\n", i + 1);
        }

        free(ciphertext);
    }

    return 0;
}
