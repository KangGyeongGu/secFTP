#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "connection.h"

// 클라이언트 소켓 초기화 및 서버 연결 함수
int init_client_socket(int *sock, const char *server_ip, int port) {
	struct sockaddr_in server_addr;

	// 클라이언트 소켓 생성
	*sock = socket(AF_INET, SOCK_STREAM, 0);
	if (*sock < 0) {
		perror("Socket creation failed");
		return -1;
	}

	// 서버 주소 설정
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(server_ip);
	server_addr.sin_port = htons(port);

	// 서버에 연결
	if (connect(*sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Connection failed");
		close(*sock);
		return -1;
	}

	printf("[secTCP STATUS] Connected to server %s:%d\n", server_ip, port);
	return 0;
}

// 사용자로부터 서버 주소 및 포트 번호를 입력받는 함수
void get_server_address(char *ip, int *port) {
	printf("[SERVER IP] ");
	fgets(ip, 16, stdin);
	ip[strcspn(ip, "\n")] = '\0';  // 개행 문자 제거

	printf("[SERVER PORT] ");
	scanf("%d", port);
	getchar(); // 버퍼에 남은 개행 문자 처리
}

