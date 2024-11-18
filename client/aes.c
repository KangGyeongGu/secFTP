#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "rsa.h"
#include "aes.h"
#include "login.h"
#include "connection.h"

int generate_and_encrypt_aes_key(EVP_PKEY *pubkey, int client_sock, unsigned char *aes_key) {
    if (generate_aes_key(aes_key, AES_KEY_SIZE) != 0) {
        return -1;
    }
    print_aes_key(aes_key, AES_KEY_SIZE);

    unsigned char *encrypted_aes_key = NULL;
    size_t encrypted_aes_key_len = 0;
    if (rsa_encrypt_aes_key(pubkey, aes_key, AES_KEY_SIZE, &encrypted_aes_key, &encrypted_aes_key_len) != 0) {
        return -1;  
    }

    if (send_encrypted_message(client_sock, encrypted_aes_key, encrypted_aes_key_len) != 0) {
        free(encrypted_aes_key); 
        return -1;
    }

    printf("[CLIENT STATUS] RSA_Encrypted AES key sending....\n");

    free(encrypted_aes_key); 
    return 0;
}

int generate_aes_key(unsigned char *key, size_t key_len) {
	if (key_len != AES_KEY_SIZE) {
		fprintf(stderr, "Invalid key length\n");
		return -1;
	}
	if (RAND_bytes(key, key_len) != 1) {
		fprintf(stderr, "Error generating AES key\n");
		return -1;
	}
	return 0; 
}

int generate_aes_iv(unsigned char *iv, size_t iv_len) {
	if (iv_len != AES_BLOCK_SIZE) {
		fprintf(stderr, "Invalid IV length\n");
		return -1;
	}
	if (RAND_bytes(iv, iv_len) != 1) {
		fprintf(stderr, "Error generating IV\n");
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
                fprintf(stderr, "Error during final decryption\n");
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
	printf("[CLIENT STATUS] AES Key : ");
	for (size_t i = 0; i < key_len; i++) {
		printf("%02x", key[i]);
	}
	printf("\n");
}

void print_aes_iv(const unsigned char *iv, size_t iv_len) {
	printf("[CLIENT STATUS] AES IV : ");
	for (size_t i = 0; i < iv_len; i++) {
		printf("%02x", iv[i]);
	}
	printf("\n");
}

