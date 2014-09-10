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

//int cryp_sock_fd = 0;
//int dec_sock_fd = 0;

char send_buffer[BUFFER_SIZE];
char recv_buffer[BUFFER_SIZE];

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
    UNEXPECTED
} 
Error_t;



char *                                                                                                                                                                  
generate_passkey();
#endif
