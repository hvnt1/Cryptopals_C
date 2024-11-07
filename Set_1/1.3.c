// Single-byte XOR cipher
// The hex encoded string:

// 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
// ... has been XOR'd against a single character. Find the key, decrypt the message.

// You can do this by hand. But don't: write code to do it for you.

// How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Function to convert hex character to its integer value
int hex_to_int(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Convert a hex-encoded string to a byte array
int hex_to_bytes(const char *hex, unsigned char *bytes) {
    int len = strlen(hex) / 2;
    for (int i = 0; i < len; i++) {
        bytes[i] = (hex_to_int(hex[2 * i]) << 4) | hex_to_int(hex[2 * i + 1]);
    }
    return len;
}

// Score plaintext based on character frequency
int score_plaintext(const char *plaintext, int len) {
    int score = 0;
    const char *frequency_chars = "ETAOIN SHRDLU";
    for (int i = 0; i < len; i++) {
        if (strchr(frequency_chars, toupper(plaintext[i]))) score++;
        else if (isprint(plaintext[i])) score += 0;
        else score -= 10;
    }
    return score;
}

// Decrypt using single-byte XOR and find the best key
void single_byte_xor_decrypt(const unsigned char *ciphertext, int cipher_len, int* best_score, char* best_plaintext) {
    unsigned char best_key = 0;

    // Try each possible key
    for (unsigned char key = 0; key < 255; key++) {
        char plaintext[256];
        
        for (int i = 0; i < cipher_len; i++) {
            plaintext[i] = ciphertext[i] ^ key;
        }
        
        int score = score_plaintext(plaintext, cipher_len);
        
        if (score > *best_score) {
            *best_score = score;
            best_key = key;
            strncpy(best_plaintext, plaintext, cipher_len);
            best_plaintext[cipher_len] = '\0'; // Null-terminate string
        }
    }

}

int main() {
    const char *hex_ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    unsigned char ciphertext[256];

    int score = -1000;
    char plaintext[256];
    
    int cipher_len = hex_to_bytes(hex_ciphertext, ciphertext);
    single_byte_xor_decrypt(ciphertext, cipher_len, &score, plaintext);

    printf("%s - Score: %d\n", plaintext, score);
    
    return 0;
}
