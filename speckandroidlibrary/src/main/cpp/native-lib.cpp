#include <jni.h>
#include <string>
#include <android/log.h>
#include "speck.h"
#include "speck_api.h"

// Function to convert a jstring (Java string) to a C-style string (const char*)
const char *jstringToCString(JNIEnv *env, jstring javaString) {
    return env->GetStringUTFChars(javaString, nullptr);
}

// Function to release a C-style string after use
void releaseCString(JNIEnv *env, jstring javaString, const char *cString) {
    env->ReleaseStringUTFChars(javaString, cString);
}

// Helper function to remove spaces from the input string
char *removeSpaces(const char *input) {
    size_t inputLength = strlen(input);
    char *stringWithoutSpaces = (char *)malloc(inputLength + 1);  // Allocate memory for the cleaned string

    size_t j = 0;
    for (size_t i = 0; i < inputLength; i++) {
        if (!isspace((unsigned char)input[i])) {  // Copy only non-space characters
            stringWithoutSpaces[j++] = input[i];
        }
    }
    stringWithoutSpaces[j] = '\0';  // Null-terminate the cleaned string

    return stringWithoutSpaces;
}

// Function to handle key length (96-bit or 128-bit)
// If the key is 128-bit (32 hex chars), it truncates it to the first 96 bits (24 hex chars).
char *handleKey(const char *keyHex) {
    // Remove spaces from the input key
    char *keyWithoutSpaces = removeSpaces(keyHex);
    size_t keyLength = strlen(keyWithoutSpaces);

    char *key96 = nullptr;

    if (keyLength == 24) {
        // Key is already 96-bit, return a copy of it
        key96 = (char *)malloc(25);  // Allocate memory for the key (96-bit + null terminator)
        strcpy(key96, keyWithoutSpaces);  // Copy the key as it is
    } else if (keyLength == 32) {
        // Key is 128-bit, truncate to 96-bit
        key96 = (char *)malloc(25);  // Allocate memory for the truncated key (96-bit + null terminator)
        strncpy(key96, keyWithoutSpaces, 24);  // Copy the first 24 characters (96 bits)
        key96[24] = '\0';  // Null-terminate the string
    }

    // Free the keyWithoutSpaces to prevent memory leaks
    free(keyWithoutSpaces);

    // Return the 96-bit key or nullptr if the length was invalid
    return key96;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_speckandroidlibrary_SpeckCipher_encrypt(
        JNIEnv *env,
        jobject /* this */,
        jstring plaintext,
        jstring key) {

    // Convert the plaintext and key from jstring (Java) to const char* (C)
    const char *plaintextHex = jstringToCString(env, plaintext);
    const char *keyHex = jstringToCString(env, key);

    // Handle key size (96-bit or 128-bit)
    char *processedKeyHex = handleKey(keyHex);
    if (processedKeyHex == nullptr) {
        // Release the Java string memory and return NULL in case of an invalid key size
        releaseCString(env, plaintext, plaintextHex);
        releaseCString(env, key, keyHex);
        return nullptr;  // Return null if the key length is invalid
    }

    // Encrypt
    char *ciphertext = speck_encrypt(plaintextHex, processedKeyHex);

    // Release the Java string memory used for input
    releaseCString(env, plaintext, plaintextHex);
    releaseCString(env, key, keyHex);

    // Convert the ciphertext (C string) to a jstring (Java string)
    jstring result = env->NewStringUTF(ciphertext);

    // Free the allocated memory for ciphertext
    free(ciphertext);

    // Return the encrypted ciphertext as a jstring
    return result;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_speckandroidlibrary_SpeckCipher_decrypt(
        JNIEnv *env,
        jobject /* this */,
        jstring ciphertext,
        jstring key) {

    // Convert the ciphertext and key from jstring (Java) to const char* (C)
    const char *ciphertextHex = jstringToCString(env, ciphertext);
    const char *keyHex = jstringToCString(env, key);

    // Handle key size (96-bit or 128-bit)
    char *processedKeyHex = handleKey(keyHex);
    if (processedKeyHex == nullptr) {
        // Release the Java string memory and return NULL in case of an invalid key size
        releaseCString(env, ciphertext, ciphertextHex);
        releaseCString(env, key, keyHex);
        return nullptr;  // Return null if the key length is invalid
    }

    // Decrypt
    char *plaintext = speck_decrypt(ciphertextHex, processedKeyHex);

    // Release the Java string memory used for input
    releaseCString(env, ciphertext, ciphertextHex);
    releaseCString(env, key, keyHex);

    // Convert the plaintext (C string) to a jstring (Java string)
    jstring result = env->NewStringUTF(plaintext);

    // Free the allocated memory for plaintext
    free(plaintext);

    // Return the decrypted plaintext as a jstring
    return result;
}
