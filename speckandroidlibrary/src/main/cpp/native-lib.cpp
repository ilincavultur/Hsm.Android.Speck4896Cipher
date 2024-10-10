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

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_speckandroidlibrary_SpeckCipher_encrypt(
        JNIEnv *env,
        jobject /* this */,
        jstring plaintext,
        jstring key) {

    // Convert the plaintext and key from jstring (Java) to const char* (C)
    const char *plaintextHex = jstringToCString(env, plaintext);
    const char *keyHex = jstringToCString(env, key);

    // Call the platform-independent speck_encrypt function
    char *ciphertext = speck_encrypt(plaintextHex, keyHex);

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

    // Call the platform-independent speck_decrypt function
    char *plaintext = speck_decrypt(ciphertextHex, keyHex);

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
