// Implement CBC mode
// CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

// In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

// The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

// Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

// The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

#include <openssl/aes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

// Block size for AES
#define BLOCK_SIZE 16

// XOR function for two byte arrays
void xor_blocks(unsigned char *out, const unsigned char *in1, const unsigned char *in2, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = in1[i] ^ in2[i];
    }
}

// Padding function to add PKCS padding
void pad(unsigned char *block, size_t original_len, size_t padded_len) {
    unsigned char pad_byte = padded_len - original_len;
    for (size_t i = original_len; i < padded_len; i++) {
        block[i] = pad_byte;
    }
}

// Encrypt a message in CBC mode
void cbc_encrypt(const unsigned char *plaintext, size_t len, unsigned char *ciphertext, const unsigned char *key, const unsigned char *iv) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key); // Set AES encryption key (128-bit)

    unsigned char block[BLOCK_SIZE];
    unsigned char prev_block[BLOCK_SIZE];
    memcpy(prev_block, iv, BLOCK_SIZE); // Start with IV

    size_t num_blocks = (len + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (size_t i = 0; i < num_blocks; i++) {
        // Copy plaintext block (or pad the last block)
        size_t block_len = BLOCK_SIZE;
        if (i == num_blocks - 1 && len % BLOCK_SIZE != 0) {
            block_len = len % BLOCK_SIZE;
            memcpy(block, plaintext + i * BLOCK_SIZE, block_len);
            pad(block, block_len, BLOCK_SIZE);
        } else {
            memcpy(block, plaintext + i * BLOCK_SIZE, BLOCK_SIZE);
        }

        // XOR block with previous ciphertext (or IV for the first block)
        xor_blocks(block, block, prev_block, BLOCK_SIZE);

        // Encrypt block in ECB mode
        AES_encrypt(block, ciphertext + i * BLOCK_SIZE, &aes_key);

        // Update previous block for the next round
        memcpy(prev_block, ciphertext + i * BLOCK_SIZE, BLOCK_SIZE);
    }
}

// Decrypt a message in CBC mode
void cbc_decrypt(const unsigned char *ciphertext, size_t len, unsigned char *plaintext, const unsigned char *key, const unsigned char *iv) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key); // Set AES decryption key (128-bit)

    unsigned char block[BLOCK_SIZE];
    unsigned char prev_block[BLOCK_SIZE];
    memcpy(prev_block, iv, BLOCK_SIZE); // Start with IV

    for (size_t i = 0; i < len / BLOCK_SIZE; i++) {
        // Decrypt ciphertext block in ECB mode
        AES_decrypt(ciphertext + i * BLOCK_SIZE, block, &aes_key);

        // XOR with previous ciphertext block (or IV for the first block)
        xor_blocks(block, block, prev_block, BLOCK_SIZE);

        // Copy decrypted block to plaintext output
        memcpy(plaintext + i * BLOCK_SIZE, block, BLOCK_SIZE);

        // Update previous block
        memcpy(prev_block, ciphertext + i * BLOCK_SIZE, BLOCK_SIZE);
    }

    // Remove PKCS#7 padding if needed
    size_t pad_len = plaintext[len - 1];
    if (pad_len > 0 && pad_len <= BLOCK_SIZE) {
        memset(plaintext + len - pad_len, 0, pad_len);
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

// Base64 decoding function
int base64_decode(const char *input, unsigned char *output) {
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

    return length;
}

// Main function to demonstrate CBC encryption and decryption
int main() {
    // key and IV
    unsigned char key[BLOCK_SIZE] = "YELLOW SUBMARINE";
    unsigned char iv[BLOCK_SIZE] = {0};

    // Example plaintext
    const char *plaintext = "This is a message that needs to be encrypted with CBC mode";
    size_t plaintext_len = strlen(plaintext);

    // Allocate memory for ciphertext and decrypted text
    size_t ciphertext_len = ((plaintext_len + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
    unsigned char *ciphertext = malloc(ciphertext_len);
    unsigned char *decryptedtext = malloc(ciphertext_len);

    // Encrypt the plaintext
    cbc_encrypt((const unsigned char *)plaintext, plaintext_len, ciphertext, key, iv);

    // Decrypt the ciphertext
    cbc_decrypt(ciphertext, ciphertext_len, decryptedtext, key, iv);

    // Print the results
    printf("Ciphertext (hex): ");
    for (size_t i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    printf("Decrypted text: %s\n", decryptedtext);

    // Free allocated memory
    free(ciphertext);
    free(decryptedtext);

    // Decrypt the file:
    size_t buffer_size;
    const char* encoded = read_file("2.2.txt", &buffer_size);
    unsigned char decoded_ciphertext[10024];

    base64_decode(encoded, decoded_ciphertext);

    unsigned char *decryptedtext2 = malloc(buffer_size);

    // Decrypt the ciphertext
    cbc_decrypt(decoded_ciphertext, buffer_size, decryptedtext2, key, iv);

    printf("Decrypted text: %s\n", decryptedtext2);

    free(decryptedtext2);

    return 0;
}
