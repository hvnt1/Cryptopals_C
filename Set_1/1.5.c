// Implement repeating-key XOR
// Here is the opening stanza of an important work of the English language:

// Burning 'em, if you ain't quick and nimble
// I go crazy when I hear a cymbal
// Encrypt it, under the key "ICE", using repeating-key XOR.

// In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

// It should come out to:

// 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
// a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
// Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.

#include <stdio.h>
#include <string.h>

// Function to perform repeating-key XOR encryption
void repeating_key_xor(const char *plaintext, const char *key, unsigned char *ciphertext) {
    size_t text_len = strlen(plaintext);
    size_t key_len = strlen(key);

    for (size_t i = 0; i < text_len; i++) {
        // XOR the current byte of plaintext with the corresponding key byte
        ciphertext[i] = plaintext[i] ^ key[i % key_len];
    }
}

// Function to convert the encrypted bytes to a hex string for display
void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex_output) {
    for (size_t i = 0; i < len; i++) {
        sprintf(&hex_output[i * 2], "%02x", bytes[i]);
    }
}

int main() {
    const char *plaintext = "Burning 'em, if you ain't quick and nimble\n"
                            "I go crazy when I hear a cymbal";

    const char *key = "ICE";

    unsigned char ciphertext[strlen(plaintext)];

    repeating_key_xor(plaintext, key, ciphertext);

    char hex_output[strlen(plaintext) * 2 + 1];
    hex_output[strlen(plaintext) * 2] = '\0'; 

    bytes_to_hex(ciphertext, strlen(plaintext), hex_output);

    printf("%s\n", hex_output);

    return 0;
}
