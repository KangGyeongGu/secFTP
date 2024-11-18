#ifndef LOGIN_H
#define LOGIN_H

#include <openssl/evp.h>

int login_process(int client_sock, EVP_PKEY *pkey);

// 입력 문자열을 command, username, userpwd로 파싱하는 함수
int parse_input(const char *input, char *command, char *username, char *userpwd);

// 회원가입 처리 함수
int handle_join(const char *username, const char *userpwd);

// 로그인 처리 함수
int handle_login(const char *username, const char *userpwd);

#endif // LOGIN_H

