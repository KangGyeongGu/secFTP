#ifndef AES_H
#define AES_H

#include <stddef.h>

#define AES_KEY_SIZE 32   // AES-256 키 길이 (32 바이트)
#define AES_BLOCK_SIZE 16 // AES 블록 크기 (16 바이트)

int generate_and_encrypt_aes_key(EVP_PKEY *pubkey, int client_sock, unsigned char *aes_key);

// AES 대칭키 생성
int generate_aes_key(unsigned char *key, size_t key_len);

// AES IV 생성
int generate_aes_iv(unsigned char *iv, size_t iv_len);

// AES로 데이터 암호화
int aes_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext);

// AES로 데이터 복호화
int aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext);

// AES 키 출력
void print_aes_key(const unsigned char *key, size_t key_len);

// AES IV 출력
void print_aes_iv(const unsigned char *iv, size_t iv_len);

#endif

