// login.h
#ifndef LOGIN_H
#define LOGIN_H

#include <stddef.h> 

// 로그인 프로세스를 수행하는 함수 선언
int login_process(int client_sock, EVP_PKEY *pubkey);

// 사용자 입력을 받는 함수
void get_user_input(char *input, size_t size);

// 암호화된 메시지를 서버로 전송하는 함수
int send_encrypted_message(int client_sock, unsigned char *encrypted_data, int encrypted_data_len);

#endif  // LOGIN_H

