#ifndef HASH_H
#define HASH_H

#include <openssl/evp.h>

int generate_salt(unsigned char *salt, size_t salt_len);

int hash_password_with_salt(const char *password, const unsigned char *salt, size_t salt_len, unsigned char *hashed_password);

#endif // HASH_H

