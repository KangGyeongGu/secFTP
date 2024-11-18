#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/socket.h>

#define PUB_KEY_FILE "public_key.pem"   // 공개키 파일 경로


int rsa_decrypt(EVP_PKEY *privkey, unsigned char *encrypted_data, size_t encrypted_data_len, unsigned char *decrypted_data, size_t *decrypted_data_len) {
	EVP_PKEY_CTX *ctx = NULL;
	int ret = -1;
	size_t outlen = 0;

	ctx = EVP_PKEY_CTX_new(privkey, NULL);
	if (ctx == NULL) {
		fprintf(stderr, "Error creating EVP_PKEY_CTX\n");
		return ret;
	}
	
	if (EVP_PKEY_decrypt_init(ctx) <= 0) {
		fprintf(stderr, "Error initializing decryption\n");
		goto cleanup;
	}

	if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted_data, encrypted_data_len) <= 0) {
		fprintf(stderr, "Error determining output length\n");
		goto cleanup;
	}

	if (EVP_PKEY_decrypt(ctx, decrypted_data, &outlen, encrypted_data, encrypted_data_len) <= 0) {
		fprintf(stderr, "Error decrypting data\n");
		goto cleanup;
	}

	*decrypted_data_len = outlen;
	ret = 0;

cleanup:
	if (ctx) EVP_PKEY_CTX_free(ctx);
	return ret;
}


EVP_PKEY* generate_rsa_keys() {
	EVP_PKEY *pkey = NULL;         
	EVP_PKEY_CTX *pkey_ctx = NULL;

	pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!pkey_ctx || EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
		perror("Failed to initialize keygen context");
		EVP_PKEY_CTX_free(pkey_ctx);
		return NULL;
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) <= 0) {
		perror("Failed to set RSA keygen bits");
		EVP_PKEY_CTX_free(pkey_ctx);
		return NULL;
	}

	if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
		perror("Failed to generate RSA key");
		EVP_PKEY_CTX_free(pkey_ctx);
		return NULL;
	}

	EVP_PKEY_CTX_free(pkey_ctx);

	return pkey;  
}

int send_public_key(int client_sock, EVP_PKEY *pkey) {
	BIO *bio = BIO_new(BIO_s_mem()); 
	if (bio == NULL) {
		perror("Failed to create memory BIO");
		return -1;
	}

	if (PEM_write_bio_PUBKEY(bio, pkey) <= 0) {
		perror("Failed to write public key to BIO");
		BIO_free(bio);
		return -1;
	}

	char *pub_key_data;
	long pub_key_len = BIO_get_mem_data(bio, &pub_key_data);

	if (send(client_sock, pub_key_data, pub_key_len, 0) < 0) {
		perror("Failed to send public key to client");
		BIO_free(bio);
		return -1;
	}

	BIO_free(bio); 
	return 0;
}

void print_public_key(EVP_PKEY *pkey) {
	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);  
	PEM_write_bio_PUBKEY(bio, pkey); 
	BIO_free(bio);  
}

void print_private_key(EVP_PKEY *pkey) {
	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE); 
	PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL); 
	BIO_free(bio); 
}

