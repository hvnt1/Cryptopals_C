// Convert hex to base64
// The string:
// 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
// Should produce:
// SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
// So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
// Cryptopals Rule
// Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t *byte_len) {
    size_t len = strlen(hex);
    *byte_len = len / 2;
    for (size_t i = 0; i < len; i += 2) {
        sscanf(hex + i, "%2hhx", &bytes[i / 2]);
    }
}

void bytes_to_base64(const unsigned char *bytes, size_t byte_len, char *base64) {
    size_t i, j;
    int val;
    size_t b64_len = ((byte_len + 2) / 3) * 4;

    for (i = 0, j = 0; i < byte_len;) {
        val = bytes[i++] << 16;
        if (i < byte_len) val |= bytes[i++] << 8;
        if (i < byte_len) val |= bytes[i++];

        base64[j++] = base64_table[(val >> 18) & 0x3F];
        base64[j++] = base64_table[(val >> 12) & 0x3F];
        base64[j++] = (i > byte_len + 1) ? '=' : base64_table[(val >> 6) & 0x3F];
        base64[j++] = (i > byte_len) ? '=' : base64_table[val & 0x3F];
    }
    base64[b64_len] = '\0';
}

int main() {
    const char *hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    unsigned char bytes[1024];
    size_t byte_len;
    char base64[2048];

    hex_to_bytes(hex, bytes, &byte_len);
    bytes_to_base64(bytes, byte_len, base64);

    printf("Hex: %s\n", hex);
    printf("Base64: %s\n", base64);

    return 0;
}
