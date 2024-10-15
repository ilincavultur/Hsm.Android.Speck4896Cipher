package com.example.speckandroidlibrary

import androidx.test.platform.app.InstrumentationRegistry
import com.example.speckandroidlibrary.SpeckCipher.decrypt
import com.example.speckandroidlibrary.SpeckCipher.encrypt
import org.junit.Assert
import org.junit.Test

// Results:

// CipherText(Plaintext-1, Key-1)
private const val ENCRYPTED_RESULT_ONE = "BE 28 69 0E B6 E5"
private val ENCRYPTED_RESULT_ONE_NO_SPACES = ENCRYPTED_RESULT_ONE.replace(" ", "")

// CipherText(Plaintext-1, Key-2)
private const val ENCRYPTED_RESULT_TWO = "42 AE 06 2C D7 0C"
private val ENCRYPTED_RESULT_TWO_NO_SPACES = ENCRYPTED_RESULT_TWO.replace(" ", "")

// CipherText(Plaintext-2, Key-1)
private const val ENCRYPTED_RESULT_THREE = "DC BA 43 84 1F E5"
private val ENCRYPTED_RESULT_THREE_NO_SPACES = ENCRYPTED_RESULT_THREE.replace(" ", "")

// CipherText(Plaintext-2, Key-2)
private const val ENCRYPTED_RESULT_FOUR = "2F 24 47 5F 80 7E"
private val ENCRYPTED_RESULT_FOUR_NO_SPACES = ENCRYPTED_RESULT_FOUR.replace(" ", "")

// Data set 1
val plaintext1 = "01 02 03 04 05 06"
val key1 =
    "00 00 00 00 00 00 00 00 00 00 00 00"
val key1_no_spaces =
    key1.replace(" ", "")
val key1_128 =
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
val key1_128_no_spaces =
    key1_128.replace(" ", "")

// Data set 2
val plaintext2 = "FF EE 99 88 33 22"
val key2 =
    "00 11 22 33 44 55 66 77 88 99 aa bb"
val key2_no_spaces =
    key2.replace(" ", "")
val key2_128 =
    "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"
val key2_128_no_spaces =
    key2_128.replace(" ", "")

class SpeckInstrumentedTest {

    // Encryption

    @Test
    fun encryptData_plaintextOneKeyOne96_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_ONE
        val encryptedData = encrypt(plaintext1, key1)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextOneKeyOneNoSpaces96_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_ONE
        val encryptedData = encrypt(plaintext1, key1_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextOneKeyOne128_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_ONE
        val encryptedData = encrypt(plaintext1, key1_128)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextOneKeyOneNoSpaces128_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_ONE
        val encryptedData = encrypt(plaintext1, key1_128_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextOneKeyTwo96_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_TWO
        val encryptedData = encrypt(plaintext1, key2)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextOneKeyTwoNoSpaces96_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_TWO
        val encryptedData = encrypt(plaintext1, key2_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextOneKeyTwo128_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_TWO
        val encryptedData = encrypt(plaintext1, key2_128)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextOneKeyTwoNoSpaces128_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_TWO
        val encryptedData = encrypt(plaintext1, key2_128_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextTwoKeyOne96_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_THREE
        val encryptedData = encrypt(plaintext2, key1)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextTwoKeyOne96NoSpaces_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_THREE
        val encryptedData = encrypt(plaintext2, key1_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextTwoKeyOne128_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_THREE
        val encryptedData = encrypt(plaintext2, key1_128)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextTwoKeyOne128NoSpaces_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_THREE
        val encryptedData = encrypt(plaintext2, key1_128_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextTwoKeyTwo96_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_FOUR
        val encryptedData = encrypt(plaintext2, key2)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextTwoKeyTwo96NoSpaces_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_FOUR
        val encryptedData = encrypt(plaintext2, key2_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextTwoKeyTwo128_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_FOUR
        val encryptedData = encrypt(plaintext2, key2_128)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun encryptData_plaintextTwoKeyTwo128NoSpaces_ReturnsExpectedString() {
        val expectedResult = ENCRYPTED_RESULT_FOUR
        val encryptedData = encrypt(plaintext2, key2_128_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    // Decryption

    @Test
    fun decryptData_plaintextOneKeyOne96_ReturnsExpectedString() {
        val expectedResult = plaintext1
        val encryptedData = decrypt(ENCRYPTED_RESULT_ONE, key1)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextOneKeyOne96NoSpaces_ReturnsExpectedString() {
        val expectedResult = plaintext1
        val encryptedData = decrypt(ENCRYPTED_RESULT_ONE_NO_SPACES, key1_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextOneKeyOne128_ReturnsExpectedString() {
        val expectedResult = plaintext1
        val encryptedData = decrypt(ENCRYPTED_RESULT_ONE, key1_128)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextOneKeyOne128NoSpaces_ReturnsExpectedString() {
        val expectedResult = plaintext1
        val encryptedData = decrypt(ENCRYPTED_RESULT_ONE_NO_SPACES, key1_128_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextOneKeyTwo96_ReturnsExpectedString() {
        val expectedResult = plaintext1
        val encryptedData = decrypt(ENCRYPTED_RESULT_TWO, key2)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextOneKeyTwo96NoSpaces_ReturnsExpectedString() {
        val expectedResult = plaintext1
        val encryptedData = decrypt(ENCRYPTED_RESULT_TWO_NO_SPACES, key2_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextOneKeyTwo128_ReturnsExpectedString() {
        val expectedResult = plaintext1
        val encryptedData = decrypt(ENCRYPTED_RESULT_TWO, key2_128)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextOneKeyTwo128NoSpaces_ReturnsExpectedString() {
        val expectedResult = plaintext1
        val encryptedData = decrypt(ENCRYPTED_RESULT_TWO_NO_SPACES, key2_128_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextTwoKeyOne96_ReturnsExpectedString() {
        val expectedResult = plaintext2
        val encryptedData = decrypt(ENCRYPTED_RESULT_THREE, key1)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextTwoKeyOne96NoSpaces_ReturnsExpectedString() {
        val expectedResult = plaintext2
        val encryptedData = decrypt(ENCRYPTED_RESULT_THREE_NO_SPACES, key1_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextTwoKeyOne128_ReturnsExpectedString() {
        val expectedResult = plaintext2
        val encryptedData = decrypt(ENCRYPTED_RESULT_THREE, key1_128)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextTwoKeyOne128NoSpaces_ReturnsExpectedString() {
        val expectedResult = plaintext2
        val encryptedData = decrypt(ENCRYPTED_RESULT_THREE_NO_SPACES, key1_128_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextTwoKeyTwo96_ReturnsExpectedString() {
        val expectedResult = plaintext2
        val encryptedData = decrypt(ENCRYPTED_RESULT_FOUR, key2)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextTwoKeyTwo96NoSpaces_ReturnsExpectedString() {
        val expectedResult = plaintext2
        val encryptedData = decrypt(ENCRYPTED_RESULT_FOUR_NO_SPACES, key2_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextTwoKeyTwo128_ReturnsExpectedString() {
        val expectedResult = plaintext2
        val encryptedData = decrypt(ENCRYPTED_RESULT_FOUR, key2_128)

        Assert.assertEquals(expectedResult, encryptedData)
    }

    @Test
    fun decryptData_plaintextTwoKeyTwo128NoSpaces_ReturnsExpectedString() {
        val expectedResult = plaintext2
        val encryptedData = decrypt(ENCRYPTED_RESULT_FOUR_NO_SPACES, key2_128_no_spaces)

        Assert.assertEquals(expectedResult, encryptedData)
    }

}