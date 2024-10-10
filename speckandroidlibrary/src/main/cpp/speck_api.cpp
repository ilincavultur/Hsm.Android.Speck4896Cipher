//
// Created by Ilinca Vultur on 08.10.24.
//
#include <cstring>
#include <cstdio>
#include <malloc.h>
#include "speck_api.h"
#include "speck.h"  // The speck.h from the repository

// Helper function to convert hexadecimal string to bytes
void hexToBytes(const char *hexString, uint8_t *byteArray, size_t byteArrayLength) {
    for (size_t i = 0; i < byteArrayLength; i++) {
        sscanf(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
}

// Helper function to convert byte array to hex string (with spaces)
char *bytesToHex(const uint8_t *byteArray, size_t byteArrayLength) {
    size_t hexStringLength = byteArrayLength * 3;  // 2 hex digits + space for each byte
    char *hexString = (char *) malloc(hexStringLength + 1);  // +1 for null terminator

    for (size_t i = 0; i < byteArrayLength; i++) {
        sprintf(hexString + (i * 3), "%02x ", byteArray[i]);  // Convert each byte to hex with space
    }

    hexString[hexStringLength - 1] = '\0';  // Null-terminate the string
    return hexString;
}

char *speck_encrypt(const char *plaintextHex, const char *keyHex) {
    // Create reusable cipher object for Speck 96/48
    SimSpk_Cipher my_speck_cipher;

    // Initialize IV and Counter Values (if needed, for modes like CTR, here for ECB it’s unused)
    uint8_t my_IV[] = {0x32, 0x14, 0x76, 0x58};
    uint8_t my_counter[] = {0x2F, 0x3D, 0x5C, 0x7B};

    // Speck 96/48 specifics
    const int BLOCK_SIZE = 6;  // 48 bits (6 bytes)
    const int KEY_SIZE = 12;   // 96 bits (12 bytes)

    // Buffers for plaintext, key, and ciphertext
    uint8_t speck96_48_plain[BLOCK_SIZE];     // 6 bytes (48 bits)
    uint8_t speck96_48_key[KEY_SIZE];         // 12 bytes (96 bits)
    uint8_t ciphertext_buffer[BLOCK_SIZE];    // Output buffer (48 bits = 6 bytes)

    // Ensure plaintext and key lengths are as expected (hex string length should be double the byte array length)
    size_t plaintextHexLength = strlen(plaintextHex);
    size_t keyHexLength = strlen(keyHex);

    if (plaintextHexLength != 2 * BLOCK_SIZE || keyHexLength != 2 * KEY_SIZE) {
        return strdup("Error: Invalid plaintext or key size.");
    }

    // Convert the plaintext and key from hex string to byte array
    hexToBytes(plaintextHex, speck96_48_plain, BLOCK_SIZE);  // Convert hex to bytes
    hexToBytes(keyHex, speck96_48_key, KEY_SIZE);            // Convert hex to bytes

    // Initialize the cipher with the key and mode
    Speck_Init(&my_speck_cipher, cfg_96_48, ECB, speck96_48_key, my_IV, my_counter);

    // Encrypt the plaintext using Speck
    Speck_Encrypt(my_speck_cipher, speck96_48_plain, ciphertext_buffer);

    // Convert ciphertext to a hexadecimal string (with spaces)
    char *ciphertextString = bytesToHex(ciphertext_buffer, BLOCK_SIZE);

    return ciphertextString;  // Return the ciphertext as a hex-encoded string
}

// Decrypt function implementation (platform-independent)
char *speck_decrypt(const char *ciphertextHex, const char *keyHex) {
    // Create reusable cipher object for Speck 96/48
    SimSpk_Cipher my_speck_cipher;

    // Initialize IV and Counter Values (if needed, for modes like CTR, here for ECB it’s unused)
    uint8_t my_IV[] = {0x32, 0x14, 0x76, 0x58};
    uint8_t my_counter[] = {0x2F, 0x3D, 0x5C, 0x7B};

    // Speck 96/48 specifics
    const int BLOCK_SIZE = 6;  // 48 bits (6 bytes)
    const int KEY_SIZE = 12;   // 96 bits (12 bytes)

    // Buffers for ciphertext, key, and plaintext
    uint8_t speck96_48_cipher[BLOCK_SIZE];     // 6 bytes (48 bits)
    uint8_t speck96_48_key[KEY_SIZE];          // 12 bytes (96 bits)
    uint8_t plaintext_buffer[BLOCK_SIZE];      // Output buffer (48 bits = 6 bytes)

    // Ensure key length is as expected (hex string length should be double the byte array length)
    size_t ciphertextHexLength = strlen(ciphertextHex);
    size_t keyHexLength = strlen(keyHex);

    if (ciphertextHexLength != 2 * BLOCK_SIZE || keyHexLength != 2 * KEY_SIZE) {
        return strdup("Error: Invalid ciphertext or key size.");
    }

    // Convert the ciphertext and key from hex string to byte array
    hexToBytes(ciphertextHex, speck96_48_cipher, BLOCK_SIZE);  // Convert hex to bytes
    hexToBytes(keyHex, speck96_48_key, KEY_SIZE);              // Convert hex to bytes

    // Initialize the cipher with the key and mode
    Speck_Init(&my_speck_cipher, cfg_96_48, ECB, speck96_48_key, my_IV, my_counter);

    // Decrypt the ciphertext using Speck
    Speck_Decrypt(my_speck_cipher, speck96_48_cipher, plaintext_buffer);

    // Convert plaintext buffer back to a hexadecimal string (with spaces)
    char *plaintextString = bytesToHex(plaintext_buffer, BLOCK_SIZE);

    return plaintextString;  // Return the decrypted plaintext as a hex-encoded string
}
