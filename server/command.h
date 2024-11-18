#ifndef COMMAND_H
#define COMMAND_H

#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32

int command_parse(const char *command, char *cmd, char *path1, char *file1, char *path2, char *file2);

int command_handler(int client_sock, unsigned char *aes_key);

int send_handler(int client_sock, const char *path2, const char *file2, unsigned char *aes_key, unsigned char *iv);

int recv_handler(int client_sock, const char *path2, const char *file2, unsigned char *aes_key, unsigned char *iv);

#endif

