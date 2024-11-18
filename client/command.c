#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "command.h"
#include "aes.h"
#include "connection.h"
#include "login.h"
#include "response.h"

int command_handler(int client_sock, unsigned char *aes_key) {
	int count = 1;
	while (1) {
		printf("[CLIENT STATUS] USER'S %d COMMAND]\n", count++);
		unsigned char iv[AES_BLOCK_SIZE];
		char command[1024], cmd[32], path1[1024], file1[256], path2[1024], file2[256];

		if (generate_aes_iv(iv, AES_BLOCK_SIZE) != 0) {
			fprintf(stderr, "Error generating IV\n");
			return -1;
		}
		print_aes_iv(iv, AES_BLOCK_SIZE);  
		if (send(client_sock, iv, AES_BLOCK_SIZE, 0) != AES_BLOCK_SIZE) {
			fprintf(stderr, "Error sending IV to server\n");
			return -1;
		}


		if (get_command(command, sizeof(command)) != 0) {
			fprintf(stderr, "Error getting command\n");
			return -1;
		}

		if (strcmp(command, "quit") == 0) {
			strcpy(cmd, "quit");
		} else {
			if (command_parse(command, cmd, path1, file1, path2, file2) != 0) {
				fprintf(stderr, "Invalid command format\n");
				return -1;
			}
		}


		unsigned char encrypted_command[1024];
		int encrypted_command_len = aes_encrypt((unsigned char *)command, strlen(command), aes_key, iv, encrypted_command);
		if (encrypted_command_len < 0) {
			fprintf(stderr, "Error encrypting command\n");
			return -1;
		}

		if (send(client_sock, encrypted_command, encrypted_command_len, 0) != encrypted_command_len) {
			fprintf(stderr, "Error sending encrypted command to server\n");
			return -1;
		}


		if (strcmp(cmd, "send") == 0) {
			if (receive_valid_response(client_sock) != 0) {
				fprintf(stderr, "command is wrong....\n");
				return -1;
			}

			if (send_handler(client_sock, command, path1, file1, aes_key, iv) != 0) {
				printf("send_handler failed! not 0\n");
				return -1;
			}
			continue;
		}
		else if (strcmp(cmd, "recv") == 0) {
			if (receive_valid_response(client_sock) != 0) {
				fprintf(stderr, "command is wrong....\n");
				return -1;
			}

			if (recv_handler(client_sock, command, path1, file1, aes_key, iv) != 0) {
				return -1;
			}

			continue;
		}
		else if (strcmp(cmd, "quit") == 0) {
			printf("[CLIENT STATUS] User excuse QUIT....\n");
			return 0;
		}
		else {
			if (receive_valid_response(client_sock) != 0) {
				fprintf(stderr, "[CLIENT STATUS] Invalid command, try again...\n");
				continue;
			}
		}

	}
}

int get_command(char *command, size_t size) {
	printf("[COMMAND] ");
	if (fgets(command, size, stdin) == NULL) {
		perror("Error reading command");
		return -1;
	}
	size_t len = strlen(command);
	if (len > 0 && command[len - 1] == '\n') {
		command[len - 1] = '\0';
	}
	return 0;
}


// (2) 명령어를 파싱하는 메서드
int command_parse(const char *command, char *cmd, char *path1, char *file1, char *path2, char *file2) {
	char command_copy[1024];
	strncpy(command_copy, command, sizeof(command_copy));

	char *token = strtok(command_copy, " ");
	if (token == NULL) {
		return -1;
	}
	strcpy(cmd, token);

	token = strtok(NULL, " ");
	if (token == NULL) {
		return -1;
	}

	char *slash_pos = strchr(token, '/');
	if (slash_pos == NULL) {
		return -1; 
	}

	*slash_pos = '\0'; 
	strcpy(path1, token); 
	strcpy(file1, slash_pos + 1); 

	token = strtok(NULL, " ");
	if (token == NULL) {
		return -1;
	}

	slash_pos = strchr(token, '/');
	if (slash_pos == NULL) {
		return -1; 
	}

	*slash_pos = '\0'; 
	strcpy(path2, token); 
	strcpy(file2, slash_pos + 1); 

	return 0; 
}


int send_handler(int client_sock, const char* command, const char *path1, const char *file1, unsigned char *aes_key, unsigned char *iv) {
	char full_path1[1024];
	snprintf(full_path1, sizeof(full_path1), "%s/%s", path1, file1);

	if (access(full_path1, F_OK) == -1) {
		fprintf(stderr, "File %s does not exist.\n", full_path1);
		return -1;
	}

	struct stat file_stat;
	if (stat(full_path1, &file_stat) == -1) {
		perror("Error getting file size");
		return -1;
	}
	off_t file_size = file_stat.st_size;

	if (send(client_sock, &file_size, sizeof(file_size), 0) != sizeof(file_size)) {
		fprintf(stderr, "Error sending file size to server\n");
		return -1;
	}

	int file_fd = open(full_path1, O_RDONLY);
	if (file_fd == -1) {
		perror("Error opening file");
		return -1;
	}


	// "_ENC" 확장자를 추가한 암호화 파일 경로 생성
	char enc_file_path[1024];
	snprintf(enc_file_path, sizeof(enc_file_path), "%s/ENC_%s", path1, file1);


	// 암호화된 파일 저장용 "_ENC" 파일 열기
	int enc_file_fd = open(enc_file_path, O_WRONLY | O_CREAT, 0666);
	if (enc_file_fd == -1) {
		perror("Error opening encrypted file for writing");
		close(file_fd);
		return -1;
	}


	unsigned char file_buffer[16];
	ssize_t read_len;

	uint32_t bytes_send = 0;
	while ((read_len = read(file_fd, file_buffer, 16)) > 0) {
		unsigned char encrypted_data[32];

		// (1) Encrypt plaintext
		int encrypted_len = aes_encrypt(file_buffer, read_len, aes_key, iv, encrypted_data);
		if (encrypted_len < 0) {
			fprintf(stderr, "Error encrypting file data\n");
			close(file_fd);
			return -1;
		}

		// (2) Write Cypertext in ENC_file of client's Dir
                for (ssize_t i = 0; i < encrypted_len; i++) {
                        char hex_str[3];
                        snprintf(hex_str, sizeof(hex_str), "%02X", file_buffer[i]); 
                        if (write(enc_file_fd, hex_str, 2) != 2) {
                                fprintf(stderr, "Error writing encrypted hex data to file\n");
                                close(file_fd);
                                close(enc_file_fd);
                                return -1;
                        }
                }

		// (3) Send to server
		if (send(client_sock, encrypted_data, encrypted_len, 0) != encrypted_len) {
			fprintf(stderr, "Error sending encrypted file data to server\n");
			close(file_fd);
			return -1;
		}

		bytes_send += read_len;
		printf("[ send: %u / %lu bytes ]\n", bytes_send, file_size);
	}
	printf("\n");

	close(file_fd);
	return 0;
}


int recv_handler(int client_sock, const char *command, const char *path1, const char *file1, unsigned char *aes_key, unsigned char *iv) {
	struct stat st = {0};
	if (stat(path1, &st) == -1) {
		if (mkdir(path1, 0777) != 0) {
			perror("Error creating directory");
			return -1;
		}
	}

	unsigned char file_buffer[32];
	ssize_t read_len;

	// "_ENC" 확장자를 추가한 암호화 파일 경로 생성
	char enc_file_path[1024];
	snprintf(enc_file_path, sizeof(enc_file_path), "%s/ENC_%s", path1, file1);


	off_t file_size;
	if (recv(client_sock, &file_size, sizeof(file_size), 0) != sizeof(file_size)) {
		fprintf(stderr, "Error receiving file size\n");
		return -1;
	}

	char full_path1[1024];
	snprintf(full_path1, sizeof(full_path1), "%s/%s", path1, file1);

	int file_fd = open(full_path1, O_WRONLY | O_CREAT, 0666);
	if (file_fd == -1) {
		perror("Error opening file for writing");
		return -1;
	}

	// 암호화된 파일 저장용 "_ENC" 파일 열기
	int enc_file_fd = open(enc_file_path, O_WRONLY | O_CREAT, 0666);
	if (enc_file_fd == -1) {
		perror("Error opening encrypted file for writing");
		close(file_fd);
		return -1;
	}

	unsigned char decrypted_data[AES_BLOCK_SIZE];
	uint32_t bytes_received = 0;
	while (bytes_received != file_size) {
		read_len = recv(client_sock, file_buffer, 32, 0);
		if (read_len <= 0) {
			fprintf(stderr, "Error receiving file data\n");
			close(file_fd);
			return -1;
		}

		// 수신된 암호화된 데이터를 16진수 텍스트로 변환하여 "_ENC" 파일에 저장
		for (ssize_t i = 0; i < read_len; i++) {
			char hex_str[3];
			snprintf(hex_str, sizeof(hex_str), "%02X", file_buffer[i]); // 각 바이트를 16진수로 변환
			if (write(enc_file_fd, hex_str, 2) != 2) {
				fprintf(stderr, "Error writing encrypted hex data to file\n");
				close(file_fd);
				close(enc_file_fd);
				return -1;
			}
		}

		int decrypted_len = aes_decrypt(file_buffer, read_len, aes_key, iv, decrypted_data);
		if (decrypted_len < 0) {
			fprintf(stderr, "Error decrypting file data\n");
			close(file_fd);
			return -1;
		}

		if (write(file_fd, decrypted_data, decrypted_len) != decrypted_len) {
			fprintf(stderr, "Error writing decrypted data to file\n");
			close(file_fd);
			return -1;
		}

		bytes_received += decrypted_len; 

		printf("[ Received: %u / %lu bytes ]\n",bytes_received, file_size);
	}
	printf("\n");

	close(file_fd);
	return 0;

}
