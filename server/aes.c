#include "aes.h"
#include "rsa.h"
#include "connection.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>
// 클라이언트로부터 암호화된 AES 키를 수신하고 복호화하는 함수
int receive_and_decrypt_aes_key(EVP_PKEY *privkey, int client_sock, unsigned char *decrypted_aes_key, size_t *decrypted_aes_key_len) {
	unsigned char buffer[BUFFER_SIZE];

	ssize_t encrypted_aes_key_len = recv(client_sock, buffer, BUFFER_SIZE, 0);
	if (encrypted_aes_key_len <= 0) {
		perror("[SYSTEM ERROR] Error receiving encrypted AES key\n");
		return -1;
	}

	if (rsa_decrypt(privkey, buffer, encrypted_aes_key_len, decrypted_aes_key, decrypted_aes_key_len) != 0) {
		fprintf(stderr, "[SYSTEM ERROR] Error decrypting AES key\n");
		return -1;
	}

	printf("[SYSTEM] Decrypted AES key: ");
	for (size_t i = 0; i < *decrypted_aes_key_len; i++) {
		printf("%02x", decrypted_aes_key[i]);
	}
	printf("\n");

	return 0;
}

int generate_aes_key(unsigned char *key, size_t key_len) {
	if (key_len != AES_KEY_SIZE) {
		fprintf(stderr, "[SYSTEM ERROR] Invalid key length\n");
		return -1;
	}
	if (RAND_bytes(key, key_len) != 1) {
		fprintf(stderr, "[SYSTEM ERROR] Error generating AES key\n");
		return -1;
	}
	return 0;
}

int generate_aes_iv(unsigned char *iv, size_t iv_len) {
	if (iv_len != AES_BLOCK_SIZE) {
		fprintf(stderr, "[SYSTEM ERROR] Invalid IV length\n");
		return -1;
	}
	if (RAND_bytes(iv, iv_len) != 1) {
		fprintf(stderr, "[SYSTEM ERROR] Error generating IV\n");
		return -1;
	}
	return 0; 
}

int aes_encrypt(const unsigned char *plaintext, size_t plaintext_len,
		const unsigned char *key, const unsigned char *iv,
		unsigned char *ciphertext) {

	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());

	int padding_len = block_size - (plaintext_len % block_size);
	unsigned char *padded_plaintext = NULL;

	if (padding_len != block_size) {
		padded_plaintext = (unsigned char *)malloc(plaintext_len + padding_len);
		if (padded_plaintext == NULL) { 
			EVP_CIPHER_CTX_free(ctx); 
			return -1;
		}

		memcpy(padded_plaintext, plaintext, plaintext_len);
		memset(padded_plaintext + plaintext_len, padding_len, padding_len);
		plaintext_len += padding_len;
	} else { 
		padded_plaintext = (unsigned char *)plaintext; 
	}

	if (EVP_EncryptUpdate(ctx, ciphertext, &len, padded_plaintext, plaintext_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		if (padded_plaintext != plaintext) {
			free(padded_plaintext); 
		}
		return -1;
	}
	ciphertext_len = len;

	if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		if (padded_plaintext != plaintext) {
			free(padded_plaintext);
		}
		return -1;
	}
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	if (padded_plaintext != plaintext) {
		free(padded_plaintext);
	}

	return ciphertext_len;
}

int aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
		const unsigned char *key, const unsigned char *iv,
		unsigned char *plaintext) {
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;

	if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	plaintext_len = len;

	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		fprintf(stderr, "[SYSTEM ERROR] Error during final decryption\n");
		return -1;
	}
	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	int padding_len = plaintext[plaintext_len - 1];
	if (padding_len > 0 && padding_len <= EVP_CIPHER_block_size(EVP_aes_256_cbc())) {
		plaintext_len -= padding_len;  
	}

	return plaintext_len; 
}

void print_aes_key(const unsigned char *key, size_t key_len) {
	printf("[SERVER STATUS] AES KEY : ");
	for (size_t i = 0; i < key_len; i++) {
		printf("%02x", key[i]);
	}
	printf("\n");
}

void print_aes_iv(const unsigned char *iv, size_t iv_len) {
	printf("[SERVER STATUS] AES IV : ");
	for (size_t i = 0; i < iv_len; i++) {
		printf("%02x", iv[i]);
	}
	printf("\n");
}

