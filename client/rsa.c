// rsa.c
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

EVP_PKEY* receive_public_key_struct(int client_sock) {
	char buffer[2048];
	int bytes_received = recv(client_sock, buffer, sizeof(buffer), 0);
	if (bytes_received < 0) {
		perror("Failed to receive public key from server");
		return NULL;
	}

	BIO *bio = BIO_new_mem_buf(buffer, bytes_received);
	if (bio == NULL) {
		perror("Failed to create BIO for public key");
		return NULL;
	}

	EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free(bio);

	if (pubkey == NULL) {
		perror("Failed to read public key");
		return NULL;
	}

	return pubkey;
}

int rsa_encrypt(EVP_PKEY *pubkey, const char *input, unsigned char **encrypted_data, size_t *encrypted_data_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (ctx == NULL) {
        perror("Failed to create EVP_PKEY_CTX");
        return -1;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        perror("Failed to initialize encryption");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, encrypted_data_len, (unsigned char *)input, strlen(input)) <= 0) {
        perror("Failed to determine encrypted data length");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    *encrypted_data = (unsigned char *)malloc(*encrypted_data_len);
    if (*encrypted_data == NULL) {
        perror("Failed to allocate memory for encrypted data");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, *encrypted_data, encrypted_data_len, (unsigned char *)input, strlen(input)) <= 0) {
        perror("Encryption failed");
        EVP_PKEY_CTX_free(ctx);
        free(*encrypted_data);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int rsa_encrypt_aes_key(EVP_PKEY *pubkey, const unsigned char *aes_key, size_t aes_key_len, unsigned char **encrypted_data, size_t *encrypted_data_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (ctx == NULL) {
        perror("Failed to create EVP_PKEY_CTX");
        return -1;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        perror("Failed to initialize encryption");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, encrypted_data_len, aes_key, aes_key_len) <= 0) {
        perror("Failed to determine encrypted data length");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    *encrypted_data = (unsigned char *)malloc(*encrypted_data_len);
    if (*encrypted_data == NULL) {
        perror("Failed to allocate memory for encrypted data");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, *encrypted_data, encrypted_data_len, aes_key, aes_key_len) <= 0) {
        perror("Encryption failed");
        EVP_PKEY_CTX_free(ctx);
        free(*encrypted_data);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return 0;
}


void print_public_key(EVP_PKEY *pubkey) {
	if (pubkey == NULL) {
		fprintf(stderr, "Public key is NULL\n");
		return;
	}

	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE); 
	if (bio == NULL) {
		perror("Failed to create BIO for output");
		return;
	}

	if (PEM_write_bio_PUBKEY(bio, pubkey) == 0) {
		perror("Failed to write public key");
	}

	BIO_free(bio);
}

