#ifndef CONNECTION_H
#define CONNECTION_H

#include <arpa/inet.h>

// 기본적인 버퍼 크기 정의
#define BUFFER_SIZE 4096

// 서버 소켓 초기화 및 클라이언트 연결 수락 함수
int init_server_and_accept(int *server_sock, int *client_sock, struct sockaddr_in *client_addr, int port, const char *ip);

#endif // CONNECTION_H

