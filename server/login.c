#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "login.h"
#include "hash.h"
#include "rsa.h"
#include "connection.h"
#include "response.h"

#define BUFFER_SIZE 4096
#define SHA512_DIGEST_LENGTH 64
#define SALT_LEN 32

int login_process(int client_sock, EVP_PKEY *pkey) {
	char buffer[BUFFER_SIZE];

	while (1) {
		ssize_t bytes_received = recv(client_sock, buffer, sizeof(buffer), 0);
		if (bytes_received <= 0) {
			perror("[SYSTEM ERROR] Error receiving encrypted message.\n");
			break;
		}

		unsigned char decrypted_message[BUFFER_SIZE];
		size_t decrypted_message_len = 0;
		if (rsa_decrypt(pkey, (unsigned char *)buffer, bytes_received, decrypted_message, &decrypted_message_len) != 0) {
			fprintf(stderr, "[SYSTEM ERROR] Error decrypting message.\n");
			break;
		}
		decrypted_message[decrypted_message_len] = '\0';

		char command[BUFFER_SIZE], username[BUFFER_SIZE], userpwd[BUFFER_SIZE];
		if (parse_input((char *)decrypted_message, command, username, userpwd) != 0) {
			fprintf(stderr, "[SYSTEM ERROR] Error parsing message.\n");
			break;
		}

		if (strcmp(command, "join") == 0) {
			if (handle_join(username, userpwd) == 0) {
				send_valid_response(client_sock);
				printf("[AUTHENTICATION] User {%s} successfully joined.\n", username);
				return 0;
			} else {
				send_invalid_response(client_sock);
				fprintf(stderr, "[AUTHENTICATION] User already registered in Server.\n");
				continue;
			}
		} else if (strcmp(command, "login") == 0) {
			if (handle_login(username, userpwd) == 0) {
				send_valid_response(client_sock);
				printf("[AUTHENTICATION] User {%s} successfully logged in.\n", username);
				return 0;
			} else {
				send_invalid_response(client_sock);
				fprintf(stderr, "[AUTHENTICATION] retry username or userpassword.\n");
				continue;
			}
		} else {
			send_invalid_response(client_sock);
			fprintf(stderr, "[AUTHENTICATION] Unknown command: %s\n", command);
			continue;
		}
	}
}

int parse_input(const char *input, char *command, char *username, char *userpwd) {
	int ret = 0;
	char *token;
	char *input_copy = strdup(input);

	token = strtok(input_copy, " ");
	if (token == NULL) {
		ret = -1;
		goto cleanup;
	}
	strcpy(command, token);

	token = strtok(NULL, " ");
	if (token == NULL) {
		ret = -1;
		goto cleanup;
	}
	strcpy(username, token);

	// password 파싱
	token = strtok(NULL, " ");
	if (token == NULL) {
		ret = -1;
		goto cleanup;
	}
	strcpy(userpwd, token);

cleanup:
	free(input_copy);
	return ret;
}

// 회원 가입 처리 함수
int handle_join(const char *username, const char *userpwd) {

	FILE *password_file = fopen("password.txt", "a+");
	if (password_file == NULL) {
		perror("[SYSTEM ERROR] Error opening password file");
		return -1;
	}

	char line[256];
	unsigned char stored_salt[SALT_LEN];
	unsigned char stored_hash[SHA512_DIGEST_LENGTH];
	char stored_username[256];

	while (fgets(line, sizeof(line), password_file)) {
		line[strcspn(line, "\n")] = '\0';

		char *token = strtok(line, ":");
		if (token == NULL) continue;  

		strncpy(stored_username, token, sizeof(stored_username));
		token = strtok(NULL, ":");
		if (token == NULL) continue; 
		for (int i = 0; i < SALT_LEN; i++) {
			sscanf(token + i * 2, "%2hhx", &stored_salt[i]);
		}

		token = strtok(NULL, ":");
		if (token == NULL) continue; 
		for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
			sscanf(token + i * 2, "%2hhx", &stored_hash[i]);
		}

		if (strcmp(stored_username, username) == 0) {
			return -1;
		}
	}

	unsigned char salt[SALT_LEN];
	if (generate_salt(salt, SALT_LEN) != 0) {
		fprintf(stderr, "[SYSTEM ERROR] Salt generation failed.\n");
		fclose(password_file);
		return -1;
	}

	unsigned char hashed_password[SHA512_DIGEST_LENGTH];
	if (hash_password_with_salt(userpwd, salt, SALT_LEN, hashed_password) != 0) {
		fprintf(stderr, "[SYSTEM ERROR] userpwd hash compute failed.\n");
		fclose(password_file);
		return -1;
	}

	// username, salt, hashed_password 저장
	fprintf(password_file, "%s:", username);
	for (int i = 0; i < SALT_LEN; i++) {
		fprintf(password_file, "%02x", salt[i]);
	}
	fprintf(password_file, ":");
	for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
		fprintf(password_file, "%02x", hashed_password[i]);
	}
	fprintf(password_file, "\n");

	fclose(password_file);

	return 0;
}

// 로그인 처리 함수
int handle_login(const char *username, const char *userpwd) {

	FILE *file = fopen("password.txt", "r");
	if (file == NULL) {
		perror("[SYSTEM ERROR] Error opening password.txt");
		return -1;
	}

	char line[256];
	unsigned char stored_salt[SALT_LEN];
	unsigned char stored_hash[SHA512_DIGEST_LENGTH];
	char stored_username[256];

	while (fgets(line, sizeof(line), file)) {
		line[strcspn(line, "\n")] = '\0';

		char *token = strtok(line, ":");
		if (token == NULL) continue;
		strncpy(stored_username, token, sizeof(stored_username));
		token = strtok(NULL, ":");
		if (token == NULL) continue; 
		for (int i = 0; i < SALT_LEN; i++) {
			sscanf(token + i * 2, "%2hhx", &stored_salt[i]);
		}

		token = strtok(NULL, ":");
		if (token == NULL) continue; 
		for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
			sscanf(token + i * 2, "%2hhx", &stored_hash[i]);
		}

		if (strcmp(stored_username, username) == 0) {
			unsigned char computed_hash[SHA512_DIGEST_LENGTH];

			if (hash_password_with_salt(userpwd, stored_salt, SALT_LEN, computed_hash) != 0) {
				printf("[SYSTEM ERROR] Error hashing password.\n");
				fclose(file);
				return -1; 
			}
			if (memcmp(stored_hash, computed_hash, SHA512_DIGEST_LENGTH) == 0) {
				fclose(file);
				return 0; 
			} else {
				fclose(file);
				return -1; 
			}
		}
	}

	fclose(file);
	return -1; 
}
