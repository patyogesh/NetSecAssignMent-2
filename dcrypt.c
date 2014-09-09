#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include "common.h"

#define HOW_TO_USE {\
    printf("gatorcrypt <input file> [-d < port >][-l] \n\n"); \
    printf("Description: \n\n");\
    printf(" -d < port > :\n");\
    printf("     Listening port \n");\
    printf(" -l :\n");\
    printf("     Local Mode: decode local file \n");\
}

Error_t
wait_for_secure_connection(int server_port, FILE *fptr)
{
    Error_t ret_status = SUCCESS;

    int conn_fd;
    int sock_len = 0;
    int read_bytes = 0;

    struct sockaddr_in client_addr;

    dec_sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(dec_sock_fd < 0) {

	printf("\n Error opening socket");
	return SOCKET_FAIL;
    }

    memset(&server_addr, '0', sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(server_port);

    ret_status = bind( dec_sock_fd, 
	    	      (struct sockaddr *) &server_addr, 
		      sizeof(server_addr));

    if(ret_status < 0) {

	printf("\n Error binding socket");
	return BIND_FAIL;
    }

    ret_status = listen(dec_sock_fd, 10);

    if(ret_status < 0) {

	printf("lister Failed \n");
	return LISTEN_FAIL;
    }

    sock_len = sizeof(struct sockaddr_in);

    conn_fd = accept( dec_sock_fd, 
	    	     (struct sockaddr *) &client_addr, 
		     (socklen_t *) &sock_len);

    if(conn_fd < 0) {
	printf(" ERROR: accept failed \n");
	return ACCEPT_FAIL;
    }
	
    printf(" Success: accept success \n");
    
    read_bytes = recv(conn_fd, recv_buffer, BUFFER_SIZE, 0);
    printf(" Read %d \n", read_bytes);
    while(read_bytes > 0) {
	puts(recv_buffer);
    	read_bytes = recv(conn_fd, recv_buffer, BUFFER_SIZE, 0);
    }

    if(read_bytes == -1) {
	printf("Receive Failed\n");
	return RECV_FAIL;
    }

    printf("Client Disconnected\n");
    fflush(stdout);

    return SUCCESS;
}


int main(int argc, char *argv[])
{
    Error_t ret_status = SUCCESS;

    int server_port = 0;

    if(argc < 2) {
	printf("ERROR: Insufficient Arguments\n");
	HOW_TO_USE;
	return FAILURE;
    }

    FILE *fptr = NULL;
    fptr = fopen(argv[1], "r+");
    
    /*if(NULL == fptr) {

	printf("ERROR: Error while opening input file %s, please check if file exists\n", argv[1]); 
	return FOPEN_FAIL;
    }*/

    server_port = atoi(argv[2]);

    ret_status = wait_for_secure_connection(server_port, fptr);

    if(SUCCESS != ret_status) {
	printf("Connection establishment failed \n");
	return FAILURE;
    }

    return 0;
}
