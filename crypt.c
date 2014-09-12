#include "common.h"

#define FREE(buf) {\
    if(buf) {\
	free(buf);\
	buf = NULL;\
    }\
}

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
init_secure_connection(Enc_Dec_Apparatus_t *enc, int server_port, char *server_ip)
{
    enc->sock_id = socket(AF_INET, SOCK_STREAM, 0);

    if(enc->sock_id < 0) {

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

    if(connect(enc->sock_id, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {

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
start_data_transfer(Enc_Dec_Apparatus_t *enc,
		    int  size)
{
    ssize_t sent_bytes = 0;
    ssize_t cum_sent_bytes = 0;

    size = strlen(enc->cipher_text);

    printf("\n Cipher Size %d \t hmac %d", strlen(enc->cipher_text), strlen(enc->hmac));
    while(1) {
	
	sent_bytes = send(enc->sock_id, enc->cipher_text, size, 0);

	if(sent_bytes >= 0) {
	    cum_sent_bytes += sent_bytes;
	}

	if(cum_sent_bytes >= size) {
	    break;
	}
	
    }

    sent_bytes = send(enc->sock_id, enc->hmac, strlen(enc->hmac), 0);

    printf("\tSent : %d \n", cum_sent_bytes + sent_bytes);

    return SUCCESS;
}


int main(int argc, char *argv[])
{
    Error_t  ret_status = SUCCESS;
    int      bad_options = FALSE;
    Mode_t   mode = UNDEFINED;

    char    *server_ip = NULL;
    char    *cipher_text = NULL;
    char    *hmac = NULL;
    int     server_port = 0;
    int     f_size = 0;
    FILE    *fptr_read = NULL;

    Enc_Dec_Apparatus_t *enc = (Enc_Dec_Apparatus_t *) malloc (sizeof(Enc_Dec_Apparatus_t));

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

    generate_passkey(enc);

    if(NULL == enc->key) 
    {
	printf("Key generation Failed....exiting with 1");
	exit(1);
    }

    ret_status = encrypt_file_data(fptr_read, enc, f_size);

    if( ret_status != SUCCESS || NULL == enc->cipher_text) {
	printf("Encryption Failed....exiting with 1");
	exit(1);
    }

    ret_status = generate_hmac(enc, f_size);

    if( ret_status != SUCCESS ) {
	printf("Message Authentication....exiting with 1");
	exit(1);
    }

    switch(mode) {

	case REMOTE:
	    {
		ret_status = extract_server_ip_port(argv[3], &server_ip, &server_port);

		ret_status = init_secure_connection(enc, server_port, server_ip);

		if(SUCCESS != ret_status) {
		    printf("Connection establishment failed \n");
		    return FAILURE;
		}
		else {
		    printf("Connected !! \n");
		}

		ret_status = start_data_transfer(enc, f_size);
	    }
	    break;

	case LOCAL:
	    {
    		FILE   *fptr_write = NULL;

		strcat(argv[1], ".uf");

    		fptr_write = fopen(argv[1], "r+");
		
		if(fptr_write) {
			printf("[ERROR]: %s file already exists, exiting with error code 33\n", argv[1]);
			fclose(fptr_write);
			exit(33);
		}

    		fptr_write = fopen(argv[1], "w+");

		fwrite(enc->iv, 1, IV_LEN, fptr_write);
		fwrite(SALT, 1, SALT_LEN, fptr_write);
		fwrite(enc->cipher_text, 1, strlen(cipher_text), fptr_write);
		fwrite(enc->hmac, 1, HASH_SZ, fptr_write);

		fclose(fptr_write);

	    }
	    break;
    };
    
    FREE(enc->key);
    FREE(enc->cipher_text);
    FREE(enc->hmac);
    close(enc->sock_id);
    FREE(enc);

    fclose(fptr_read);

    return 0;
}
