#include "common.h"

#define FREE(buf) {\
    if(buf) {\
	free(buf);\
	buf = NULL;\
    }\
}

int cryp_sock_fd = 0;                                                                                                                                                   

void 
how_to_use() 
{
    printf("USAGE: \n\n");
    printf("gatorcrypt <input file> [-d < IP-addr:port >][-l] \n\n"); 
    printf("Description: \n\n");
    printf(" -d < IP-Address:port > :\n");
    printf("     Destination machine's IP and port address pair to dump file to \n");
    printf(" -l :\n");
    printf("     Local Mode: dump file to local machines\n");
}

Error_t
init_secure_connection(int server_port, char *server_ip)
{
    cryp_sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(cryp_sock_fd < 0) {

	printf("\n Error opening socket");
	return SOCKET_FAIL;
    }

    memset(&server_addr, '0', sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    if(inet_pton(AF_INET, server_ip, &server_addr.sin_addr) < 0) {

	printf("inet_pton Error\n");
	return CLIENT_FAIL;
    }

    if(connect(cryp_sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {

	printf("Error while connecting to server\n");
	return CONNECT_FAIL;
    }

    return SUCCESS;
}


Error_t
extract_server_ip_port(char *args, char **server_ip, int *server_port)
{
    int i = 0, j = 0;

    *server_ip = args;
    while(args[i] != ':') {
	i++;
    }
    args[i] = '\0';
    i++;

    char port[5];
    while(args[i]) {
	port[j] = args[i];
	j++;
	i++;
    }
    port[j] = '\0';

    *server_port = atoi(port);
    return 0;
}

Error_t
start_data_transfer(char *cipher_text,
		    char *hmac,
		    int  size)
{
    ssize_t sent_bytes = 0;
    ssize_t cum_sent_bytes = 0;

    size = strlen(cipher_text);

    printf("\n Cipher Size %d \t hmac %d", strlen(cipher_text), strlen(hmac));
    while(1) {
	
	sent_bytes = send(cryp_sock_fd, cipher_text, size, 0);

	if(sent_bytes >= 0) {
	    cum_sent_bytes += sent_bytes;
	}

	if(cum_sent_bytes >= size) {
	    break;
	}
	
    }

    sent_bytes = send(cryp_sock_fd, hmac, strlen(hmac), 0);

    printf("\tSent : %d \n", cum_sent_bytes + sent_bytes);

    return SUCCESS;
}


int main(int argc, char *argv[])
{
    Error_t  ret_status = SUCCESS;
    int      bad_options = FALSE;
    Mode_t   mode = UNDEFINED;

    char    *server_ip = NULL;
    char    *key = NULL;
    char    *cipher_text = NULL;
    char    *hmac = NULL;
    int     server_port = 0;
    int     f_size = 0;
    FILE    *fptr_read = NULL;

    if(argc < 3) {

        printf("ERROR: Insufficient/Incorrect Arguments\n");
        how_to_use();
        return FAILURE;
    }

    if(!strcmp("-d", argv[2])) 
    { 
        if(argc < 4) 
	{
            bad_options = TRUE;
        }

        mode = REMOTE;
    }
    
    else if(!strcmp("-l", argv[2])) 
    {
        mode = LOCAL;
    }

    else 
    {
        bad_options = TRUE;
    }

    if(TRUE == bad_options) {

        printf("ERROR: Insufficient/Incorrect Arguments\n");
        how_to_use();
        return FAILURE;
    }


    fptr_read = fopen(argv[1], "r+");

    if(NULL == fptr_read) 
    {
	printf("ERROR: Error while opening input file %s, please check if file exists\n", argv[1]); 
	return FOPEN_FAIL;
    }

    f_size = get_file_size(fptr_read);

    /* TODO: you have to free key Finally : DONE */
    key = generate_passkey();

    if(NULL == key) 
    {
	printf("Key generation Failed....exiting with 1");
	exit(1);
    }

    /* TODO: you have to free cipher_text after writing to file : DONE */
    cipher_text = encrypt_file_data(fptr_read, key, f_size);

    if(NULL == cipher_text) {
	printf("Encryption Failed....exiting with 1");
	exit(1);
    }

    /* TODO: you have to free hmac Finally : DONE */
    hmac = generate_hmac(cipher_text, key, f_size);

    switch(mode) {

	case REMOTE:
	    {
		ret_status = extract_server_ip_port(argv[3], &server_ip, &server_port);

		ret_status = init_secure_connection(server_port, server_ip);

		if(SUCCESS != ret_status) {
		    printf("Connection establishment failed \n");
		    return FAILURE;
		}
		else {
		    printf("Connected !! \n");
		}

		ret_status = start_data_transfer(cipher_text, hmac, f_size);
	    }
	    break;

	case LOCAL:
	    {
    		FILE   *fptr_write = NULL;
		int    write_len = strlen(cipher_text) + strlen(hmac);

		strcat(argv[1], ".uf");

    		fptr_write = fopen(argv[1], "r+");
		
		if(fptr_write) {
			printf("[ERROR]: %s file already exists, exiting with error code 33\n", argv[1]);
			fclose(fptr_write);
			exit(33);
		}

    		fptr_write = fopen(argv[1], "w+");

		cipher_text = (char *) realloc (cipher_text, write_len);

		strcat(cipher_text, hmac);
		
		fwrite(cipher_text, 1, write_len, fptr_write);

		fclose(fptr_write);

	    }
	    break;
    };
    
    FREE(key);
    FREE(cipher_text);
    FREE(hmac);

    fclose(fptr_read);
    close(cryp_sock_fd);

    return 0;
}
