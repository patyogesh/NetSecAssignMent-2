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
		    Enc_Dec_Apparatus_t  *dec,
		    FILE  *write_fptr)
{
    int read_bytes = 0;

    read_bytes = recv(conn_fd, dec->recv_buffer, BUFFER_SIZE, 0);

    if(read_bytes == -1) {
	return RECV_FAIL;
    }
    fwrite(dec->recv_buffer, 1, read_bytes, write_fptr);
    
    printf(" Read %d \n", read_bytes);

    while(read_bytes > 0) {
    	read_bytes = recv(conn_fd, dec->recv_buffer, BUFFER_SIZE, 0);
    	printf(" Read %d \n", read_bytes);
    	fwrite(dec->recv_buffer, 1, read_bytes, write_fptr);
    }

    return SUCCESS;
}

Error_t
wait_for_incoming_connection(Enc_Dec_Apparatus_t *dec,
			     int server_port, 
			     int  *conn_fd)
{
    Error_t ret_status = SUCCESS;

    int sock_len = 0;
    int read_bytes = 0;

    struct sockaddr_in client_addr;

    dec->sock_id = socket(AF_INET, SOCK_STREAM, 0);

    if(dec->sock_id < 0) {

	printf("\n Error opening socket");
	return SOCKET_FAIL;
    }

    memset(&server_addr, '0', sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(server_port);

    ret_status = bind( dec->sock_id, 
	    	      (struct sockaddr *) &server_addr, 
		      sizeof(server_addr));

    if(ret_status < 0) {

	printf("\n Error binding socket");
	return BIND_FAIL;
    }

    ret_status = listen(dec->sock_id, 10);

    if(ret_status < 0) {

	printf("lister Failed \n");
	return LISTEN_FAIL;
    }

    sock_len = sizeof(struct sockaddr_in);

    *conn_fd = accept( dec->sock_id, 
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
    Error_t	ret_status = SUCCESS;
    Mode_t  	mode = UNDEFINED;

    int		bad_options = FALSE;

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

    Enc_Dec_Apparatus_t *dec = NULL;

    ret_status = init(&dec);

    if(SUCCESS != ret_status) {
	printf("Failed to allocate memory \n");
	exit(1);
    }

    switch(mode) {

	case REMOTE:
	    {
        	int server_port = atoi(argv[3]);
		int conn_fd = 0;

		char *temp_file_name = (char *) malloc (strlen(argv[1])+3);
		strcpy(temp_file_name, argv[1]);
		strcat(temp_file_name, ".uf");

    		write_fptr = fopen(temp_file_name, "w+");

		if(NULL == write_fptr) {

		    printf("ERROR: Error while opening input file %s, please check if file exists\n", argv[1]); 
		    return FOPEN_FAIL;
		}

		ret_status = wait_for_incoming_connection(dec, server_port, &conn_fd);

		if(SUCCESS != ret_status) {
		    printf("No Incoming Connection\n");
		    return RECV_FAIL;
		}

		ret_status = receive_remote_data(conn_fd, dec, write_fptr);

		close(conn_fd);
    		close(dec->sock_id);
		fclose(write_fptr);

		if(SUCCESS != ret_status) {
		    printf("Receive Failed\n");
		    return RECV_FAIL;
		}

		generate_passkey(dec);

		if(NULL == dec->key) {
		    printf("Key generation Failed....exiting with 1");
		    exit(1);
		}

		ret_status = verify_hmac(temp_file_name, dec);

		if(SUCCESS != ret_status) {
		    printf("HMAC verification failed....exiting with error code (1) \n");
		    exit(1);
		}
		else {
		    printf("HMAC verification Success\n");
		}

		ret_status = decrypt_file_data(temp_file_name, argv[1], dec);

		if(SUCCESS != ret_status) {
		    printf("Decryption failed ....exiting with error code (1)\n");
		    exit(1);
		}

		remove(temp_file_name);

	    }
	    break;

	case LOCAL:
	    {
		FILE *fptr = fopen(argv[1], "r+");
		if(NULL == fptr) {
		    printf("File to decrypt does not exist....exiting with error code (1) \n");
		    exit(1);
		} 
		else {
		    fclose(fptr);
		}
		generate_passkey(dec);

		if(NULL == dec->key) {
		    printf("Key generation Failed....exiting with 1");
		    exit(1);
		}

		ret_status = verify_hmac(argv[1], dec);

		if(SUCCESS != ret_status) {
		    printf("HMAC verification failed....exiting with error code (1) \n");
		    exit(1);
		}
		else {
		    printf("HMAC verification Success\n");
		}

		ret_status = decrypt_file_data(argv[1], dec);

		if(SUCCESS != ret_status) {
		    printf("Decryption failed ....exiting with error code (1)\n");
		    exit(1);
		}
		else {
		    printf("Decryption Success\n");
		}
	    }
	    break;
    };


    deinit(dec);

    return SUCCESS;
}
