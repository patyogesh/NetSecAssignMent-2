#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>                                                                                                                                                 
#include <sys/types.h>                                                                                                                                                  
#include <netinet/in.h>                                                                                                                                                 
#include <netdb.h> 
#include <arpa/inet.h>
#include <gcrypt.h>

struct sockaddr_in server_addr;

#define TRUE 1
#define FALSE 0
#define BUFFER_SIZE 1024
#define SERVER_PORT 2346

#define MAX_PASSWORD_LEN 32
#define KEY_LEN 16
#define ITERATIONS 4096
#define SALT "NaCl"
#define SALT_LEN strlen(SALT)

#define IV 5844
#define IV_LEN 8
#define IV_SIZE sizeof(IV)
#define ENCRYPTION_ALGO GCRY_CIPHER_AES128
#define ENCRYPTION_MODE GCRY_CIPHER_MODE_CBC

#define HASH_ALGO GCRY_MD_SHA512
#define HASH_SZ 64

typedef enum mode {
    REMOTE,
    LOCAL,
    UNDEFINED
}
Mode_t;

typedef enum errors {
    SUCCESS,
    FAILURE,
    CLIENT_FAIL,
    SERVER_FAIL,
    SOCKET_FAIL,
    CONNECT_FAIL,
    BIND_FAIL,
    LISTEN_FAIL,
    ACCEPT_FAIL,
    RECV_FAIL,
    SEND_FAIL,
    FREAD_FAIL,
    FWRITE_FAIL,
    FOPEN_FAIL,
    HMAC_FAIL,
    UNEXPECTED
} 
Error_t;

struct enc_dec_apparatus
{
    int  sock_id;

    char *key;
    char *salt;
    char *cipher_text;
    char *hmac;
    
    unsigned long int iv;
    
    char send_buffer[BUFFER_SIZE];
    char recv_buffer[BUFFER_SIZE];
};

typedef struct enc_dec_apparatus 
		Enc_Dec_Apparatus_t;

void generate_passkey(Enc_Dec_Apparatus_t *eda);

Error_t encrypt_file_data(FILE *fptr, 
			  Enc_Dec_Apparatus_t *enc, 
			  int file_size);

Error_t generate_hmac(Enc_Dec_Apparatus_t *eda,
		      int  f_size);

#define FREE(b) {\
    if(b) {\
	free(b);\
	b = NULL;\
    }\
}
#endif
