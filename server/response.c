#include "response.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define VALID_RESPONSE "valid"
#define INVALID_RESPONSE "invalid"
#define RESPONSE_SIZE 5  // "valid"의 길이와 같음

// 클라이언트에 "valid" 응답을 전송하는 함수
int send_valid_response(int client_sock) {
    int bytes_sent = send(client_sock, VALID_RESPONSE, RESPONSE_SIZE, 0);
    if (bytes_sent == -1) {
        perror("Error sending valid response to client");
        return -1;
    }
    return 0;  // 성공
}

// 클라이언트로부터 "valid" 응답을 수신하는 함수
int receive_valid_response(int client_sock) {
    char buffer[RESPONSE_SIZE + 1] = {0};  // null terminator 추가

    int bytes_received = recv(client_sock, buffer, RESPONSE_SIZE, 0);
    if (bytes_received == -1) {
        perror("Error receiving valid response from client");
        return -1;
    }

    // 수신된 메시지가 "valid"와 일치하는지 확인
    if (strncmp(buffer, VALID_RESPONSE, RESPONSE_SIZE) == 0) {
        return 0;  // 수신 성공
    } else {
        printf("Received invalid response from client\n");
        return -1;  // 일치하지 않음
    }
}
// 클라이언트에 "invalid" 응답을 전송하는 함수
int send_invalid_response(int client_sock) {
    int bytes_sent = send(client_sock, INVALID_RESPONSE, 7, 0);
    if (bytes_sent == -1) {
        perror("Error sending valid response to client");
        return -1;
    }
    return 0;  // 성공
}

