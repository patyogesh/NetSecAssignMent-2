#include "common.h"

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
init_secure_connection(int server_port, char *server_ip, FILE *fptr)
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
start_data_transfer(FILE *fptr)
{
    size_t read_bytes;
    ssize_t sent_bytes;

    while(!feof(fptr)) {
	read_bytes = fread(send_buffer, BUFFER_SIZE, 1, fptr);

	if(read_bytes < 0) {
	    printf("File Read Failed\n");
	    return FREAD_FAIL;
	}
	
	sent_bytes = send(cryp_sock_fd, send_buffer, strlen(send_buffer), 0);

	if(sent_bytes < 0) {

	    printf("Send Failed\n");
	    return SEND_FAIL;
	}
	
    }

    return SUCCESS;
}


int main(int argc, char *argv[])
{
    Error_t ret_status = SUCCESS;
    int  bad_options = FALSE;
    Mode_t  mode = UNDEFINED;

    char *server_ip = NULL;
    int server_port = 0;

    if(argc < 3) {

        printf("ERROR: Insufficient/Incorrect Arguments\n");
        how_to_use();
        return FAILURE;
    }

    if(!strcmp("-d", argv[2])) { 

        if(argc < 4) {
            bad_options = TRUE;
        }

        mode = REMOTE;
    }
    
    else if(!strcmp("-l", argv[2])) {

        mode = LOCAL;
    }
    else {
        bad_options = TRUE;
    }

    if(TRUE == bad_options) {

        printf("ERROR: Insufficient/Incorrect Arguments\n");
        how_to_use();
        return FAILURE;
    }

    FILE *fptr = fopen(argv[1], "r+");
    
    if(NULL == fptr) {

	printf("ERROR: Error while opening input file %s, please check if file exists\n", argv[1]); 
	return FOPEN_FAIL;
    }

    ret_status = extract_server_ip_port(argv[3], &server_ip, &server_port);

    ret_status = init_secure_connection(server_port, server_ip, fptr);

    if(SUCCESS != ret_status) {
	printf("Connection establishment failed \n");
	return FAILURE;
    }
    else {
	    printf("Connected !! \n");
    }

    if(NULL == generate_passkey()) {
	printf("Key generation Failed....existing with 1");
	exit(1);
    }

    ret_status = start_data_transfer(fptr);
    
    fclose(fptr);
    close(cryp_sock_fd);

    return 0;
}
