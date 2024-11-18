#ifndef AES_H
#define AES_H

#include <openssl/evp.h>
#include <openssl/rsa.h>

#define AES_KEY_SIZE 32   // AES 256 bit key size
#define AES_BLOCK_SIZE 16 // AES block size

// 함수 선언
int receive_and_decrypt_aes_key(EVP_PKEY *privkey, int client_sock, unsigned char *decrypted_aes_key, size_t *decrypted_aes_key_len);

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


#endif // AES_H

