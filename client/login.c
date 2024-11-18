#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "login.h"
#include "rsa.h"
#include "connection.h"
#include "response.h"

// 로그인 로직을 수행하는 메서드
int login_process(int client_sock, EVP_PKEY *pubkey) {
	char input[1024];
	unsigned char *encrypted_data = NULL;
	size_t encrypted_data_len = 0;

	while (1) {
		// 사용자 입력 받기
		get_user_input(input, sizeof(input));

		// 입력 메시지를 공개키로 암호화
		if (rsa_encrypt(pubkey, input, &encrypted_data, &encrypted_data_len) != 0) {
			fprintf(stderr, "Error encrypting data\n");
			return -1;
		}

		// 암호화된 메시지를 서버로 전송
		if (send_encrypted_message(client_sock, encrypted_data, encrypted_data_len) != 0) {
			fprintf(stderr, "Error sending encrypted data\n");
			free(encrypted_data);
			return -1;
		}

		// 암호화된 데이터 메모리 해제
		free(encrypted_data);
		encrypted_data = NULL;
		encrypted_data_len = 0;

		// 서버로부터 응답 수신
		int response = receive_valid_response(client_sock);
		if (response == 0) {
			printf("[AUTHENTICATION] authentication success\n");
			return 0;
		} else if (response == 1) {
			printf("[AUTHENTICATION] Invalid login attempt. Please try again.\n");
			continue;  
		}
	}
}



// 사용자 입력을 받는 함수
void get_user_input(char *input, size_t size) {
	printf("[AUTHENTICATION] : ");
	if (fgets(input, size, stdin) == NULL) {
		perror("Error reading input");
		return;
	}

	// 입력된 문자열에서 newline 문자 제거
	input[strcspn(input, "\n")] = 0;
}

// 암호화된 메시지를 서버로 전송하는 함수
int send_encrypted_message(int client_sock, unsigned char *encrypted_data, int encrypted_data_len) {
	int bytes_sent = send(client_sock, encrypted_data, encrypted_data_len, 0);
	if (bytes_sent == -1) {
		perror("Failed to send encrypted data to server");
		return -1;
	}
	printf("[AUTHENTICATION] Try.......\n");
	return 0;
}

