#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include "common.h"

int dec_sock_fd = 0;
void how_to_use() 
{
    printf("gatorcrypt <input file> [-d < port >][-l] \n\n");
    printf("Description: \n\n");
    printf(" -d < port > :\n");
    printf("     Listening port \n");
    printf(" -l :\n");
    printf("     Local Mode: decode local file \n");
}

Error_t
receive_remote_data(int   conn_fd, 
		    char  *recv_buffer,
		    FILE  *write_fptr)
{
    int read_bytes = 0;

    read_bytes = recv(conn_fd, recv_buffer, BUFFER_SIZE, 0);

    if(read_bytes == -1) {
	return RECV_FAIL;
    }
    fwrite(recv_buffer, 1, read_bytes, write_fptr);
    
    printf(" Read %d \n", read_bytes);

    while(read_bytes > 0) {
    	read_bytes = recv(conn_fd, recv_buffer, BUFFER_SIZE, 0);
    	printf(" Read %d \n", read_bytes);
    	fwrite(recv_buffer, 1, read_bytes, write_fptr);
    }

    return SUCCESS;
}

Error_t
wait_for_secure_connection(int server_port, 
			   FILE *fptr,
			   int  *conn_fd)
{
    Error_t ret_status = SUCCESS;

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

    *conn_fd = accept( dec_sock_fd, 
	    	       (struct sockaddr *) &client_addr, 
		       (socklen_t *) &sock_len);

    if(*conn_fd < 0) {
	printf(" ERROR: accept failed \n");
	return ACCEPT_FAIL;
    }
	
    printf(" Success: accept success \n");

    return SUCCESS;
}


int main(int argc, char *argv[])
{
    Error_t ret_status = SUCCESS;

    int bad_options = FALSE;
    int server_port = 0;
    Mode_t mode = UNDEFINED;

    char    *key = NULL;

    if(argc < 3) {
        printf("ERROR: Insufficient/Incorrect Arguments\n");
        how_to_use();
        return FAILURE;
    }

    if(!strcmp("-d", argv[2])) 
    {

        if(argc < 4) { 
            bad_options = TRUE;
        }

        mode = REMOTE;
        server_port = atoi(argv[3]);
    }
    
    else if(!strcmp("-l", argv[2])) 
    {
        mode = LOCAL;
    }
    
    else {
        bad_options = TRUE;
    }

    if( TRUE == bad_options) {

        printf("ERROR: Insufficient/Incorrect Arguments\n");
        how_to_use();
        return FAILURE;
    }

    FILE *read_fptr = NULL;
    FILE *write_fptr = NULL;

    switch(mode) {

	case REMOTE:
	    {
		int conn_fd = 0;

    		write_fptr = fopen(argv[1], "w+");

		if(NULL == write_fptr) {

		    printf("ERROR: Error while opening input file %s, please check if file exists\n", argv[1]); 
		    return FOPEN_FAIL;
		}

		ret_status = wait_for_secure_connection(server_port, write_fptr, &conn_fd);

		if(SUCCESS != ret_status) {
		    printf("No Incoming Connection\n");
		    return RECV_FAIL;
		}

		ret_status = receive_remote_data(conn_fd, recv_buffer, write_fptr);
		fclose(write_fptr);

		if(SUCCESS != ret_status) {
		    printf("Receive Failed\n");
		    return RECV_FAIL;
		}

		key = generate_passkey();

		if(NULL == key) {
		    printf("Key generation Failed....existing with 1");
		    exit(1);
		}

		decrypt_file_data(argv[1], key);

		remove_hmac(argv[1]);

		verify_hmac();


		close(conn_fd);
    		close(dec_sock_fd);
	    }
	    break;

	case LOCAL:
	    {
    		read_fptr = fopen(argv[1], "w+");

		if(NULL == read_fptr) {

		    printf("ERROR: Error while opening input file %s, please check if file exists\n", argv[1]); 
		    return FOPEN_FAIL;
		}

		fclose(read_fptr);
	    }
	    break;
    };


    return 0;
}
