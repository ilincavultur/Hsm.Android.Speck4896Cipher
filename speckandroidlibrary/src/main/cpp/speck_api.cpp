////
//// Created by Ilinca Vultur on 08.10.24.
////
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include "speck_api.h"
#include "speck.h"

// Helper function to convert a single hex character to its integer value
int hex_char_to_int(char c) {

    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');

    return -1;  // Invalid hex character
}

// Helper function to convert a hex string (with optional spaces) to a byte array
int hexToBytes(const char *hexString, uint8_t *byteArray, size_t byteArrayLength) {
    size_t hexStringLength = strlen(hexString);
    size_t byteIndex = 0;

    for (size_t i = 0; i < hexStringLength; ++i) {
        if (isspace(hexString[i])) continue;  // Skip any whitespace

        if (byteIndex >= byteArrayLength) return -1;  // Check for buffer overflow

        int highNibble = hex_char_to_int(hexString[i]);
        if (highNibble == -1) return -1;  // Handle invalid character

        ++i;
        while (i < hexStringLength && isspace(hexString[i])) ++i;  // Skip spaces

        int lowNibble = hex_char_to_int(hexString[i]);
        if (lowNibble == -1) return -1;  // Handle invalid character

        byteArray[byteIndex++] = (highNibble << 4) | lowNibble;
    }

    return (int)byteIndex;  // Return the number of bytes written
}

// Helper function to convert byte array to hex string (with spaces)
char *bytesToHex(const uint8_t *byteArray, size_t byteArrayLength) {
    if (byteArray == nullptr || byteArrayLength == 0) {
        return strdup(""); // Return an empty string if input is NULL or length is 0
    }

    size_t hexStringLength = byteArrayLength * 3;  // 2 hex digits + space per byte
    char *hexString = (char *) malloc(hexStringLength + 1);  // +1 for null terminator

    for (size_t i = 0; i < byteArrayLength; i++) {
        sprintf(hexString + (i * 3), "%02X ", byteArray[i]);  // Convert byte to hex
    }

    hexString[hexStringLength - 1] = '\0';  // Null-terminate the string
    return hexString;
}

char *speck_encrypt(const char *plaintextHex, const char *keyHex) {
    // Create reusable cipher object for Speck 96/48
    SimSpk_Cipher my_speck_cipher;

    // Speck 96/48 specifics
    const int BLOCK_SIZE = 6;  // 48 bits (6 bytes)
    const int KEY_SIZE = 12;   // 96 bits (12 bytes)

    // Buffers for plaintext, key, and ciphertext
    uint8_t speck96_48_plain[BLOCK_SIZE];
    uint8_t speck96_48_key[KEY_SIZE];
    uint8_t ciphertext_buffer[BLOCK_SIZE];

    // Convert the plaintext and key from hex string to byte array
    if (hexToBytes(plaintextHex, speck96_48_plain, BLOCK_SIZE) == -1 ||
        hexToBytes(keyHex, speck96_48_key, KEY_SIZE) == -1) {
        return strdup("Error: Invalid input format.");
    }

    // Initialize the cipher with the key and mode
    Speck_Init(&my_speck_cipher, cfg_96_48, ECB, speck96_48_key, nullptr, nullptr);

    // Encrypt the plaintext using Speck
    Speck_Encrypt(my_speck_cipher, speck96_48_plain, ciphertext_buffer);

    // Convert ciphertext to a hexadecimal string (with spaces)
    char *ciphertextString = bytesToHex(ciphertext_buffer, BLOCK_SIZE);

    return ciphertextString;
}

char *speck_decrypt(const char *ciphertextHex, const char *keyHex) {
    // Create reusable cipher object for Speck 96/48
    SimSpk_Cipher my_speck_cipher;

    // Speck 96/48 specifics
    const int BLOCK_SIZE = 6;  // 48 bits (6 bytes)
    const int KEY_SIZE = 12;   // 96 bits (12 bytes)

    // Buffers for ciphertext, key, and plaintext
    uint8_t speck96_48_cipher[BLOCK_SIZE];
    uint8_t speck96_48_key[KEY_SIZE];
    uint8_t plaintext_buffer[BLOCK_SIZE];

    // Convert the ciphertext and key from hex string to byte array
    if (hexToBytes(ciphertextHex, speck96_48_cipher, BLOCK_SIZE) == -1 ||
        hexToBytes(keyHex, speck96_48_key, KEY_SIZE) == -1) {
        return strdup("Error: Invalid input format.");
    }

    // Initialize the cipher with the key and mode
    Speck_Init(&my_speck_cipher, cfg_96_48, ECB, speck96_48_key, nullptr, nullptr);

    // Decrypt the ciphertext using Speck
    Speck_Decrypt(my_speck_cipher, speck96_48_cipher, plaintext_buffer);

    // Convert plaintext to a hexadecimal string (with spaces)
    char *plaintextString = bytesToHex(plaintext_buffer, BLOCK_SIZE);

    return plaintextString;
}