#include "response.h"
#include <sys/socket.h>
#include <unistd.h>

// 클라이언트가 서버로 "valid" 응답을 전송하는 함수
int send_valid_response(int client_sock) {
    const char *valid_message = "valid";

    int bytes_sent = send(client_sock, valid_message, strlen(valid_message), 0);
    if (bytes_sent < 0) {
        perror("Error sending valid response");
        return -1;
    }

    printf("Sent 'valid' response to server\n");
    return 0;
}

// 서버 응답을 검사하여 반환
int receive_valid_response(int client_sock) {
    char response[32];
    ssize_t bytes_received = recv(client_sock, response, sizeof(response) - 1, 0);

    if (bytes_received <= 0) {
        perror("Error receiving response");
        return -1;  // 오류 발생
    }
    response[bytes_received] = '\0';

    if (strcmp(response, "valid") == 0) {
        return 0;  // 유효한 응답
    } else if (strcmp(response, "invalid") == 0) {
        return 1;  // 유효하지 않은 응답 (재입력 요청)
    } else {
        return -1;  // 기타 오류
    }
}

