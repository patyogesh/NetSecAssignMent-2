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

struct sockaddr_in server_addr;

#define BUFFER_SIZE 1024
#define SERVER_PORT 2346

int cryp_sock_fd = 0;
int dec_sock_fd = 0;

char sendBuffer[BUFFER_SIZE];
char recvBuffer[BUFFER_SIZE];

typedef enum errors {
    SUCCESS,
    FAILURE,
    CLIENT_FAIL,
    SERVER_FAIL,
    SOCKET_FAIL,
    CONNECT_FAIL,
    BIND_FAIL,
    RECV_FAIL,
    SEND_FAIL,
    FREAD_FAIL,
    FWRITE_FAIL,
    FOPEN_FAIL,
    UNEXPECTED
} 
Error_t;



#endif
