// Implement PKCS#7 padding
// A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

// One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

// So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

// "YELLOW SUBMARINE"
// ... padded to 20 bytes would be:

// "YELLOW SUBMARINE\x04\x04\x04\x04"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

unsigned char* pkcs7_pad(const unsigned char* input, size_t input_len, size_t block_size, size_t* padded_len) {
    // Calculate the required padding
    size_t padding = block_size - (input_len % block_size);
    
    // Allocate memory for the padded output
    *padded_len = input_len + padding;
    unsigned char* padded = malloc(*padded_len);
    if (!padded) {
        perror("Memory allocation failed");
        return NULL;
    }

    // Copy the input to the padded output
    memcpy(padded, input, input_len);
    
    // Append the padding bytes
    memset(padded + input_len, padding, padding);
    
    return padded;
}

int main() {
    const unsigned char* input = (const unsigned char*)"YELLOW SUBMARINE";
    size_t input_len = strlen((const char*)input);
    size_t block_size = 20;
    size_t padded_len;

    unsigned char* padded = pkcs7_pad(input, input_len, block_size, &padded_len);
    if (padded) {
        printf("Padded result: ");
        for (size_t i = 0; i < padded_len; i++) {
            if (isprint(padded[i])) {
                printf("%c", padded[i]);
            } else {
                printf("\\x%02x", padded[i]);
            }
        }
        printf("\n");

        free(padded);
    }

    return 0;
}
