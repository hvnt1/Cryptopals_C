// Detect single-character XOR
// One of the 60-character strings in this file has been encrypted by single-character XOR.

// Find it.

// (Your code from #3 should help.)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
    const char *frequency_chars = "ETAOINSHRDLU";
    
    for (int i = 0; i < len; i++) {
        if (strchr(frequency_chars, toupper(plaintext[i]))) score++;
        else if (isspace(plaintext[i])) score += 5;
        else if (isalpha(plaintext[i])) score += 0;
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

int main()
{
    // Score string
    double best_score = -1000;
    char best_plaintext[256];

    FILE *file = fopen("1.4.txt", "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    char buffer[256];
    
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        // Score string
        unsigned char ciphertext[256];

        int score = -1000;
        char plaintext[256];
        int cipher_len = hex_to_bytes(buffer, ciphertext);
        single_byte_xor_decrypt(ciphertext, cipher_len, &score, plaintext);
        if (score > best_score) {
            best_score = score;
            strncpy(best_plaintext, plaintext, cipher_len);
        }
    }
    // Close the file
    fclose(file);

    printf("%s", best_plaintext);

}
