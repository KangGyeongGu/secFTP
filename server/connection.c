#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "connection.h"

// 서버 소켓 초기화 및 클라이언트 연결 수락
int init_server_and_accept(int *server_sock, int *client_sock, struct sockaddr_in *client_addr, int port, const char *ip) {
    struct sockaddr_in server_addr;
    socklen_t client_len = sizeof(*client_addr);

    // 서버 소켓 생성
    *server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (*server_sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // 서버 주소 설정
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip);  // 서버 IP 주소
    server_addr.sin_port = htons(port);           // 서버 포트 번호

    // 소켓 바인딩
    if (bind(*server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(*server_sock);
        return -1;
    }

    // 클라이언트의 연결을 기다림
    if (listen(*server_sock, 5) < 0) {
        perror("Listen failed");
        close(*server_sock);
        return -1;
    }

    // 클라이언트 연결 수락
    *client_sock = accept(*server_sock, (struct sockaddr *)client_addr, &client_len);
    if (*client_sock < 0) {
        perror("Accept failed");
        close(*server_sock);
        return -1;
    }

    return 0;
}

