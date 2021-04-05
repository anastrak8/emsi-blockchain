#ifndef SHA256_H
#define SHA256_H
#define SHA256_DIGEST_LENGTH	64
#define EC_CURVE	NID_secp256k1
#define EC_PUB_LEN	65
#include<openssl/sha.h>
#include<openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include<stdint.h>
//SHA256
uint8_t * sha256(int8_t const * s ,size_t len , uint8_t digest[SHA256_DIGEST_LENGTH]);
//EC_KEY POINTER TO EC_KEY STRUCT :: 
EC_KEY *ec_create(void);
//EC_TO_PUBLIC ::
uint8_t *ec_to_pub(EC_KEY const *key, uint8_t pub[EC_PUB_LEN]);
//EC_FROM_PUB
EC_KEY *ec_from_pub(uint8_t const pub[EC_PUB_LEN]);
#endif

