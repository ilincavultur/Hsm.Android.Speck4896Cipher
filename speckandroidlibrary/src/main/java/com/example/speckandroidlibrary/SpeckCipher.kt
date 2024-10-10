package com.example.speckandroidlibrary

object SpeckCipher {

    init {
        // Load the native library when the object is initialized
        System.loadLibrary("speck_cipher_48_96")
    }

    /**
     * Encrypt the given plaintext using the Speck algorithm and the provided key.
     *
     * @param plaintext The plaintext to encrypt (hex string)
     * @param key The encryption key (hex string)
     * @return The encrypted ciphertext (hex string)
     */
    external fun encrypt(plaintext: String, key: String): String

    /**
     * Decrypt the given ciphertext using the Speck algorithm and the provided key.
     *
     * @param ciphertext The ciphertext to decrypt (hex string)
     * @param key The decryption key (hex string)
     * @return The decrypted plaintext (hex string)
     */
    external fun decrypt(ciphertext: String, key: String): String
}