#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "connection.h"
#include "command.h"
#include "response.h"
#include "rsa.h"
#include "aes.h"
#include "hash.h"
#include "login.h"

#define SERVER_PORT 5000
#define SERVER_IP "10.0.3.72"
#define BUFFER_SIZE 4096

int main() {
	int server_sock, client_sock;
	struct sockaddr_in client_addr;
	char buffer[BUFFER_SIZE];

	printf("\n[SERVER STATUS] Listening client's connect....\n");
	// 서버 소켓 초기화 및 클라이언트 연결 수락
	if (init_server_and_accept(&server_sock, &client_sock, &client_addr, SERVER_PORT, SERVER_IP) < 0) {
		return -1;
	}
	printf("\n[SERVER STATUS] Client connected.\n");

	printf("\n[SERVER STATUS] SERVER generating RSA key....\n");
	// RSA 키 쌍 생성
	EVP_PKEY *pkey = generate_rsa_keys();
	if (pkey == NULL) {
		fprintf(stderr, "Failed to generate RSA keys\n");
		close(client_sock);
		close(server_sock);
		return -1;
	}
	printf("\n[SERVER STATUS] RSA PUBLIC KEY SHARING....\n");

	// 공개키 전송
	if (send_public_key(client_sock, pkey) < 0) {
		fprintf(stderr, "Failed to send public key to client.\n");
		EVP_PKEY_free(pkey);
		close(client_sock);
		close(server_sock);
		return -1;
	}
	printf("\n[SERVER STATUS] RSA PUBLIC KEY SHARE SUCCESS.\n\n");

	printf("===================================RSA KEY INFO===================================\n");
	// 공개키와 개인키 출력 (디버그용)
	print_public_key(pkey);
	print_private_key(pkey);
	printf("===================================RSA KEY INFO===================================\n\n");

	printf("===================================LOGIN/JOIN=====================================\n");
	// 로그인 프로세스 처리
	if (login_process(client_sock, pkey) != 0) {
		fprintf(stderr, "Login process encountered an error.\n");
		EVP_PKEY_free(pkey);
		close(client_sock);
		close(server_sock);
		return -1;
	}
	printf("===================================LOGIN/JOIN=====================================\n\n");

	printf("===================================AES KEY INFO===================================\n");
	printf("[SERVER STATUS] client's AES KEY SHARING....\n");
	// 클라이언트로부터 AES 대칭키 공유
	unsigned char decrypted_aes_key[BUFFER_SIZE];
	size_t decrypted_aes_key_len = 0;
	if (receive_and_decrypt_aes_key(pkey, client_sock, decrypted_aes_key, &decrypted_aes_key_len) != 0) {
		fprintf(stderr, "Error receiving and decrypting AES key\n");
		EVP_PKEY_free(pkey);
		close(client_sock);
		close(server_sock);
		return -1;
	}
	printf("[SERVER STATUS] AES KEY SHARE SUCCESS.\n");
	printf("===================================AES KEY INFO===================================\n\n");


	printf("=============================[CLIENT'S SEND/RECV/QUIT]=============================\n");
	if (command_handler(client_sock, decrypted_aes_key) != 0) {
		fprintf(stderr, "command handling falied.\n");
		close(client_sock);
		close(server_sock);
		return -1;
	}
	printf("=============================[CLIENT'S SEND/RECV/QUIT]=============================\n\n");

	printf("[SERVER STATUS] secFTP connection close.\n");

	// 연결 종료
	EVP_PKEY_free(pkey);
	close(client_sock);
	close(server_sock);
	return 0;
}

