#ifndef COMMAND_H
#define COMMAND_H

#include <stdio.h>

// 명령어를 입력받는 함수
int get_command(char *command, size_t size);

// 명령어를 파싱하는 함수
int command_parse(const char *command, char *cmd, char *path1, char *file1, char *path2, char *file2);

// send 명령을 처리하는 함수
int send_handler(int client_sock, const char* command, const char *path1, const char *file1, unsigned char *aes_key, unsigned char *iv);

// recv 명령을 처리하는 함수
int recv_handler(int client_sock, const char *command, const char *path1, const char *file1, unsigned char *aes_key, unsigned char *iv);

// 명령어를 처리하는 함수
int command_handler(int client_sock, unsigned char *aes_key);

#endif // COMMAND_H

