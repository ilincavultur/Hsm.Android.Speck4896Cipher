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

// Function to handle key length (96-bit or 128-bit)
// If the key is 128-bit (32 hex chars), it truncates it to the first 96 bits (24 hex chars).
char *handleKey(const char *keyHex) {
    size_t keyLen = strlen(keyHex);

    if (keyLen == 24) {
        // Key is already 96-bit, return a copy of it
        char *key96 = (char *)malloc(25);  // Allocate memory for the key (96-bit + null terminator)
        strcpy(key96, keyHex);  // Copy the key as is
        return key96;
    } else if (keyLen == 32) {
        // Key is 128-bit, truncate to 96-bit
        char *key96 = (char *)malloc(25);  // Allocate memory for the truncated key (96-bit + null terminator)
        strncpy(key96, keyHex, 24);  // Copy the first 24 characters (96 bits)
        key96[24] = '\0';  // Null-terminate the string
        return key96;
    } else {
        // Invalid key length, return nullptr to indicate an error
        return nullptr;
    }
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

    // Call the platform-independent speck_encrypt function
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

    // Call the platform-independent speck_decrypt function
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
