// AES in ECB mode
// The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

// "YELLOW SUBMARINE".
// (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

// Decrypt it. You know the key, after all.

// Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

// Base64 decoding function
void base64_decode(const char *input, unsigned char *output) {
    BIO *bio, *b64;
    int length = strlen(input);

    // Create a BIO chain (Base64 decoder)
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, length);
    bio = BIO_push(b64, bio);

    // Decode the Base64 string into the output buffer
    length = BIO_read(bio, output, length);

    // Null-terminate the output string
    output[length] = '\0';

    // Free the BIO objects
    BIO_free_all(bio);
}

// Function to decrypt AES-128-ECB encrypted data
void aes_128_ecb_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext) {
    AES_KEY decrypt_key;
    
    // Set the AES decryption key
    if (AES_set_decrypt_key(key, 128, &decrypt_key) < 0) {
        fprintf(stderr, "Error setting AES decryption key\n");
        return;
    }
    
    // Decrypt the ciphertext
    for (int i = 0; i < ciphertext_len / 16; i++) {
        AES_ecb_encrypt(ciphertext + (i * 16), plaintext + (i * 16), &decrypt_key, AES_DECRYPT);
    }
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
    const char* encoded = read_file("1.7.txt", &buffer_size);
    const char* key = (const unsigned char*) "YELLOW SUBMARINE";
    unsigned char decoded_ciphertext[10024];
    unsigned char plaintext[10024];

    // Decode Base64 data
    base64_decode(encoded, decoded_ciphertext);
    int decoded_len = strlen((const char*)decoded_ciphertext);

    // Decrypt AES-128-ECB
    aes_128_ecb_decrypt(decoded_ciphertext, decoded_len, key, plaintext);

    printf("Decrypted text: %s\n", plaintext);

    return 0;
}

// Run with:
// gcc 1.7.c -lssl -lcrypto
