#ifndef RESPONSE_H
#define RESPONSE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RESPONSE_SIZE 1024

// 클라이언트가 서버로 "valid" 응답을 전송하는 함수
int send_valid_response(int client_sock);

// 서버로부터 "valid" 응답을 수신하는 함수
int receive_valid_response(int client_sock);

// 클라이언트가 서버로 "invalid" 응답을 전송하는 함수
int receive_invalid_response(int client_sock);

#endif

