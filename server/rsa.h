// rsa.h
#ifndef RSA_H
#define RSA_H

#include <openssl/evp.h>

int rsa_decrypt(EVP_PKEY *privkey, unsigned char *encrypted_data, size_t encrypted_data_len, unsigned char *decrypted_data, size_t *decrypted_data_len);

EVP_PKEY* generate_rsa_keys();

int send_public_key(int client_sock, EVP_PKEY *pkey);

void print_public_key(EVP_PKEY *pkey);

void print_private_key(EVP_PKEY *pkey);

#endif  // RSA_H

