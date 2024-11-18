#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "hash.h"

// 랜덤한 salt 값을 생성하는 함수
int generate_salt(unsigned char *salt, size_t salt_len) {
    if (RAND_bytes(salt, salt_len) != 1) {
        fprintf(stderr, "Error generating random salt\n");
        return -1;
    }
    return 0;  // 성공적으로 salt 생성
}

int hash_password_with_salt(const char *password, const unsigned char *salt, size_t salt_len, unsigned char *hashed_password) {
    EVP_MD_CTX *mdctx = NULL;
    unsigned char salt_and_password[SHA512_DIGEST_LENGTH + salt_len];
    int ret = -1;

    // 비밀번호와 salt를 결합
    memcpy(salt_and_password, salt, salt_len);
    memcpy(salt_and_password + salt_len, password, strlen(password));

    // SHA-512 해시 계산
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Error creating EVP_MD_CTX\n");
        return ret;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL) != 1) {
        fprintf(stderr, "Error initializing SHA-512\n");
        goto cleanup;
    }

    if (EVP_DigestUpdate(mdctx, salt_and_password, salt_len + strlen(password)) != 1) {
        fprintf(stderr, "Error updating SHA-512 hash\n");
        goto cleanup;
    }

    if (EVP_DigestFinal_ex(mdctx, hashed_password, NULL) != 1) {
        fprintf(stderr, "Error finalizing SHA-512 hash\n");
        goto cleanup;
    }

    ret = 0;  

cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    return ret;
}

