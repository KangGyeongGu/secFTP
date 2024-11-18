// rsa.h
#ifndef RSA_H
#define RSA_H

#include <openssl/evp.h>

// 서버로부터 공개키를 수신하여 EVP_PKEY 구조체로 반환
EVP_PKEY* receive_public_key_struct(int client_sock);

// 공개키로 login/join message encrypt
int rsa_encrypt(EVP_PKEY *pubkey, const char *input, unsigned char **encrypted_data, size_t *encrypted_data_len);
// aes key encrypt with RSA pubkey
int rsa_encrypt_aes_key(EVP_PKEY *pubkey, const unsigned char *aes_key, size_t aes_key_len, unsigned char **encrypted_data, size_t *encrypted_data_len);

// 공개키를 출력하는 함수
void print_public_key(EVP_PKEY *pubkey);

#endif

