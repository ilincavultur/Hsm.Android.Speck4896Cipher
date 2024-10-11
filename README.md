# Hsm.Android.Speck4896Cipher

[![](https://jitpack.io/v/ilincavultur/speck_android_48_96.svg)](https://jitpack.io/#ilincavultur/speck_android_48_96)

This project includes third-party code from the Simon_Speck_Ciphers
 by Calvin McCoy, which is licensed under the The MIT License (MIT).
The full license text for this code can be found at:
[LICENSE.md](https://github.com/inmcm/Simon_Speck_Ciphers/blob/master/LICENSE.md)

This library acts as a bridge between the C code that is written to implement the Speck Cipher and Kotlin.
It uses JNI.

Add it to your build.gradle.kts with:
```gradle
allprojects {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```
and:

```gradle
dependencies {
    implementation("com.github.ilincavultur:speck_android_48_96:{latest version}")
}
```

Usage in code:

```kotlin
val plaintext = "01 02 03 04 05 06".replace(" ", "") // 6 bytes for Speck 96/48
val key =
    "00 00 00 00 00 00 00 00 00 00 00 00".replace(" ", "") // 12 bytes for Speck 96/48

val encryptedData = SpeckCipher.encrypt(plaintext, key)
val decryptedData = SpeckCipher.decrypt(encryptedData.replace(" ", ""), key)
```

Examples to test - all values are represented as hex:

```kotlin
Plaintext-1: 01 02 03 04 05 06
Plaintext-2: ff ee 99 88 33 22

Key-1: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Key-2: 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff

CipherText(Plaintext-1, Key-1): BE 28 69 0E B6 E5
CipherText(Plaintext-1, Key-2): 42 AE 06 2C D7 0C
CipherText(Plaintext-2, Key-1): DC BA 43 84 1F E5
CipherText(Plaintext-2, Key-2): 2F 24 47 5F 80 7E
```
