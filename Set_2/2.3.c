// An ECB/CBC detection oracle
// Now that you have ECB and CBC working:

// Write a function to generate a random AES key; that's just 16 random bytes.

// Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

// The function should look like:

// encryption_oracle(your-input)
// => [MEANINGLESS JIBBER JABBER]
// Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

// Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

// Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// Function to generate a random AES key (16 bytes)
void generate_random_key(unsigned char *key) {
    RAND_bytes(key, 16);
}

// Function to generate random bytes for IV
void generate_random_iv(unsigned char *iv) {
    RAND_bytes(iv, 16);
}

// Function to randomly add padding before and after the input
unsigned char *add_random_padding(const unsigned char *input, size_t input_len, size_t *new_len) {
    int prepend_len = 5 + rand() % 6;  // Random number between 5 and 10
    int append_len = 5 + rand() % 6;   // Random number between 5 and 10
    *new_len = input_len + prepend_len + append_len;
    
    unsigned char *padded_input = (unsigned char *)malloc(*new_len);
    RAND_bytes(padded_input, prepend_len);  // Prepend random bytes
    memcpy(padded_input + prepend_len, input, input_len);  // Copy original input
    RAND_bytes(padded_input + prepend_len + input_len, append_len);  // Append random bytes
    
    return padded_input;
}

// Encrypt with AES ECB mode
void aes_ecb_encrypt(const unsigned char *key, const unsigned char *input, unsigned char *output, size_t len) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        AES_encrypt(input + i, output + i, &aes_key);
    }
}

// Encrypt with AES CBC mode
void aes_cbc_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *input, unsigned char *output, size_t len) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    unsigned char temp_iv[AES_BLOCK_SIZE];
    memcpy(temp_iv, iv, AES_BLOCK_SIZE);
    
    AES_cbc_encrypt(input, output, len, &aes_key, temp_iv, AES_ENCRYPT);
}

// Encryption Oracle that encrypts with random padding, random key, and either ECB or CBC
int encryption_oracle(const unsigned char *input, size_t input_len, unsigned char **output, size_t *output_len) {
    unsigned char key[16];
    generate_random_key(key);
    
    size_t padded_len;
    unsigned char *padded_input = add_random_padding(input, input_len, &padded_len);
    *output_len = ((padded_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;  // Pad to AES block size
    *output = (unsigned char *)malloc(*output_len);

    // Choose randomly between ECB and CBC
    int mode = rand() % 2;
    if (mode == 0) {
        aes_ecb_encrypt(key, padded_input, *output, *output_len);
    } else {
        unsigned char iv[16];
        generate_random_iv(iv);
        aes_cbc_encrypt(key, iv, padded_input, *output, *output_len);
    }
    
    free(padded_input);
    return mode;  // 0 for ECB, 1 for CBC
}

// Function to detect ECB mode by checking for repeating blocks
int detect_ecb(const unsigned char *data, size_t len) {
    size_t blocks = len / AES_BLOCK_SIZE;
    for (size_t i = 0; i < blocks - 1; i++) {
        for (size_t j = i + 1; j < blocks; j++) {
            if (memcmp(data + i * AES_BLOCK_SIZE, data + j * AES_BLOCK_SIZE, AES_BLOCK_SIZE) == 0) {
                return 1;  // Detected ECB
            }
        }
    }
    return 0;  // No repeating blocks detected
}

int main() {
    const char *plaintext = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    size_t plaintext_len = strlen(plaintext);

    unsigned char *ciphertext;
    size_t ciphertext_len;
    
    srand(time(NULL));
    
    int actual_mode = encryption_oracle((unsigned char *)plaintext, plaintext_len, &ciphertext, &ciphertext_len);
    int detected_mode = detect_ecb(ciphertext, ciphertext_len);
    
    printf("Actual mode: %s\n", actual_mode == 0 ? "ECB" : "CBC");
    printf("Detected mode: %s\n", detected_mode == 1 ? "ECB" : "CBC");
    
    free(ciphertext);
    return 0;
}
