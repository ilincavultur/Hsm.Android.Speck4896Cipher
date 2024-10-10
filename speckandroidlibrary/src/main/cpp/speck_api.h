//
// Created by Ilinca Vultur on 08.10.24.
//

#ifndef TESTSPECK_SPECK_API_H
#define TESTSPECK_SPECK_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Encrypt function for Speck 96/48
char *speck_encrypt(const char *plaintextHex, const char *keyHex);

// Decrypt function for Speck 96/48
char *speck_decrypt(const char *ciphertextHex, const char *keyHex);

#ifdef __cplusplus
}
#endif

#endif //TESTSPECK_SPECK_API_H
