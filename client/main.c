#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/evp.h>

#include "connection.h"
#include "rsa.h"
#include "aes.h"
#include "login.h"
#include "response.h"
#include "command.h"


int main() {
	int client_sock;
	char server_ip[16];
	int server_port;

	printf("=============SERVER IP/PORT=============\n");
	get_server_address(server_ip, &server_port);

	if (init_client_socket(&client_sock, server_ip, server_port) < 0) {
		return -1;
	}
	printf("[secTCP STATUS] server connection success.\n");
	printf("=============SERVER IP/PORT=============\n\n");


	printf("===================================RSA KEY INFO===================================\n");
	EVP_PKEY *pubkey = receive_public_key_struct(client_sock);
	if (pubkey == NULL) {
		fprintf(stderr, "Error receiving public key from server\n");
		close(client_sock);
		return -1;
	}
	print_public_key(pubkey);
	printf("===================================RSA KEY INFO===================================\n\n");


	printf("===================================LOGIN/JOIN=====================================\n");
	printf("(1) JOIN USERNAME USERPASSWORD\n(2) LOGIN USERNAME USERPASSWORD\n");
	char input[1024];
	unsigned char *encrypted_data = NULL;
	size_t encrypted_data_len = 0;
	int result = 0;

	if (login_process(client_sock, pubkey) != 0) {
		fprintf(stderr, "Login process failed\n");
	}
	printf("===================================LOGIN/JOIN=====================================\n\n");


	printf("===================================AES KEY INFO===================================\n");
	unsigned char aes_key[AES_KEY_SIZE];
	if (generate_and_encrypt_aes_key(pubkey, client_sock, aes_key) != 0) {
		fprintf(stderr, "Error generating and sending encrypted AES key\n");
		EVP_PKEY_free(pubkey);
		close(client_sock);
		return -1;
	}
	printf("[CLIENT STATUS] AES KEY SHARE SUCCESS.\n");
	printf("===================================AES KEY INFO===================================\n\n");


	printf("=============================[CLIENT'S SEND/RECV/QUIT]=============================\n");
	if ( command_handler(client_sock, aes_key) != 0 ) {
		fprintf(stderr, "handler error\n");
		close(client_sock);
		return -1;
	}
	printf("=============================[CLIENT'S SEND/RECV/QUIT]=============================\n");
	printf("[CLIENT STATUS] secFTP connection close.\n");

	EVP_PKEY_free(pubkey);
	close(client_sock);

	return 0;
}

