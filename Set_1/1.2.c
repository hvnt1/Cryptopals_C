// Fixed XOR
// Write a function that takes two equal-length buffers and produces their XOR combination.
// If your function works properly, then when you feed it the string:
// 1c0111001f010100061a024b53535009181c
// ... after hex decoding, and when XOR'd against:
// 686974207468652062756c6c277320657965
// ... should produce:
// 746865206b696420646f6e277420706c6179

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void hexToBytes(const char *hex, unsigned char *bytes, size_t *byteLen)
{
    size_t len = strlen(hex);
    *byteLen = len / 2;
    for (size_t i = 0; i < len; i += 2)
    {
        sscanf(hex + i, "%2hhx", &bytes[i / 2]);
    }
}

void bytesToHex(const unsigned char *bytes, size_t byteLen, char *hex)
{
    for (size_t i = 0; i < byteLen; ++i)
    {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[byteLen * 2] = '\0';
}

void fixedXOR(const unsigned char *buf1, const unsigned char *buf2, unsigned char *result, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        result[i] = buf1[i] ^ buf2[i];
    }
}

int main()
{
    const char *hex1 = "1c0111001f010100061a024b53535009181c";
    const char *hex2 = "686974207468652062756c6c277320657965";
    unsigned char bytes1[1024];
    unsigned char bytes2[1024];
    unsigned char result[1024];
    char resultHex[2048];
    size_t byteLen1, byteLen2;

    hexToBytes(hex1, bytes1, &byteLen1);
    hexToBytes(hex2, bytes2, &byteLen2);

    if (byteLen1 != byteLen2)
    {
        printf("Error: Buffers are not of equal length.\n");
        return 1;
    }

    fixedXOR(bytes1, bytes2, result, byteLen1);
    bytesToHex(result, byteLen1, resultHex);

    printf("Hex1: %s\n", hex1);
    printf("Hex2: %s\n", hex2);
    printf("Result: %s\n", resultHex);

    return 0;
}
