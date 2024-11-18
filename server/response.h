#ifndef RESPONSE_H
#define RESPONSE_H

#include <sys/socket.h>

// 클라이언트에 "valid" 응답을 전송하는 함수
int send_valid_response(int client_sock);

// 클라이언트로부터 "valid" 응답을 수신하는 함수
int receive_valid_response(int client_sock);

// 클라이언트에 "invalid" 응답을 전송하는 함수
int send_invalid_response(int client_sock);

#endif // RESPONSE_H

