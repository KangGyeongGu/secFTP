#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

// 클라이언트 소켓 초기화 및 서버 연결 함수 선언
int init_client_socket(int *sock, const char *server_ip, int port);

// 사용자로부터 서버 주소 및 포트 번호를 입력받는 함수 선언
void get_server_address(char *ip, int *port);

#endif // CONNECTION_H

