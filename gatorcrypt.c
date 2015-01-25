/************************************************************************************                                                                           
*  A Secure copy tool for local and remote copy                                     *                                                                           
*                                                                                   *                                                                           
*  http://cise.ufl.edu/class/cnt5410fa14/hw/hw2.html                                *                                                                           
*                                                                                   *                                                                           
*  Author: Yogesh Patil (ypatil@cise.ufl.edu)                                       *                                                                           
************************************************************************************/

#include "common.h"

/*
 * Utility function that prints the 'how to use'
 * the gatorcrypt and gatordec utilities
 */
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

/*
 * Initializes connection to remote machine
 * Opens socket and connects to remote machine
 */
Error_t
init_secure_connection(Enc_Dec_Apparatus_t *enc, int server_port, char *server_ip)
{
    struct sockaddr_in server_addr;

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


/*
 * Utility function to extract server IP address and port number
 * from given command line arguments
 */
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

/*
 *
 */
Error_t
start_data_transfer(Enc_Dec_Apparatus_t *enc,
		    int  size)
{
    ssize_t sent_bytes = 0;
    ssize_t cum_sent_bytes = 0;

    size += IV_LEN +
	    SALT_LEN +
	    HASH_SZ;

    enc->cipher_text = realloc(enc->cipher_text, size);

    char *ptr = enc->cipher_text;
    ptr += size - (IV_LEN + SALT_LEN + HASH_SZ);

    memcpy(ptr, &enc->iv, IV_LEN);
    ptr += IV_LEN;

    memcpy(ptr, enc->salt, SALT_LEN);
    ptr += SALT_LEN;

    memcpy(ptr, enc->hmac, HASH_SZ);


    while(1) {

        sent_bytes = send(enc->sock_id, enc->cipher_text, size, 0);

        if(sent_bytes >= 0) {
            cum_sent_bytes += sent_bytes;
        }

        if(cum_sent_bytes >= size) {
            break;
        }

    }

    enc->plain_text_len = size;

    return SUCCESS;
}


/*
 * main method for encryption
 */
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

    Enc_Dec_Apparatus_t *enc = NULL;


    /*
     * Check if sufficient arguments are provided
     */
    if(argc < 3) {

        printf("ERROR: Insufficient/Incorrect Arguments\n");
        how_to_use();
        return FAILURE;
    }

    /*
     * Check if this is copy to a remote machines
     */
    if(!strcmp("-d", argv[2])) 
    { 
        if(argc < 4) 
        {
            bad_options = TRUE;
        }

        mode = REMOTE;
    }

    /*
     * Check if this is copy to a local machines
     */
    else if(!strcmp("-l", argv[2])) 
    {
        mode = LOCAL;
    }

    /*
     * If you're here you must have provided wrong arguments
     * report an error and exit
     */
    else 
    {
        bad_options = TRUE;
    }

    if(TRUE == bad_options) {

        printf("ERROR: Insufficient/Incorrect Arguments\n");
        how_to_use();
        return FAILURE;
    }


    /*
     * Initialize encrption and decryption apparatus
     */
    ret_status = init(&enc);

    if(SUCCESS != ret_status) {
        printf("Failed to allocate memory \n");
        exit(1);
    }

    /* Open source file */
    fptr_read = fopen(argv[1], "rb");

    if(NULL == fptr_read) 
    {
        printf("ERROR: Error while opening input file %s, please check if file exists\n", argv[1]); 
        return FOPEN_FAIL;
    }

    f_size = get_file_size(fptr_read);

    enc->salt = (char *) malloc(sizeof(char) * SALT_LEN);
    strcpy(enc->salt, SALT);

    /*
     * Generate HASH key for a password
     */
    generate_passkey(enc);

    if(NULL == enc->key) 
    {
        printf("Key generation Failed....exiting with 1");
        exit(1);
    }

    /*
     * Encrypt the file data
     */
    ret_status = encrypt_file_data(fptr_read, enc, f_size);

    if( ret_status != SUCCESS || NULL == enc->cipher_text) {
        printf("Encryption Failed....exiting with 1");
        exit(1);
    }

    /*
     * Generate HMAC for encrypted data and append it to end
     */
    ret_status = generate_hmac(enc, f_size);

    if( ret_status != SUCCESS ) {
        printf("Message Authentication Failed....exiting with 1");
        exit(1);
    }

    switch(mode) {

        /*
         * If this is remote copy, open connectiont to remote machine
         * and transfer the data using socket
         */
        case REMOTE:
            {
                FILE   *fptr_write = NULL;

                char *temp_file_name = (char *) malloc (strlen(argv[1])+3);
                strcpy(temp_file_name, argv[1]);
                strcat(temp_file_name, ".uf");

                fptr_write = fopen(temp_file_name, "rb");

                if(fptr_write) {
                    printf("[ERROR]: %s file already exists, exiting with error code (33)\n", temp_file_name);
                    fclose(fptr_write);
                    exit(33);
                }

                fptr_write = fopen(temp_file_name, "wb");

                fwrite(enc->cipher_text, 1, f_size, fptr_write);
                fwrite(&enc->iv, 1, IV_LEN, fptr_write);	
                fwrite(enc->salt, 1, SALT_LEN, fptr_write);
                fwrite(enc->hmac, 1, HASH_SZ, fptr_write);

                int written = f_size + IV_LEN + SALT_LEN + HASH_SZ;
                printf("Successfully encrypted %s to %s.uf ( %u bytes written) \n ", 
                        argv[1], argv[1], written);

                ret_status = extract_server_ip_port(argv[3], &server_ip, &server_port);

                ret_status = init_secure_connection(enc, server_port, server_ip);

                if(SUCCESS != ret_status) {
                    printf("Connection establishment failed \n");
                    return FAILURE;
                }
                else {
#ifdef DEBUF
                    printf("Connected !! \n");
#endif
                }

                ret_status = start_data_transfer(enc, f_size);

                printf("Transmitting to %s:%u \n", argv[3], server_port);

                close(enc->sock_id);

                printf("Successfully Received\n");
            }
            break;

        case LOCAL:
            /*
             * If this is local copy, open local destination file
             * Write the encrypted data to that file
             */
            {
                FILE   *fptr_write = NULL;
                int    payload_len = f_size;

                char *temp_file_name = (char *) malloc (strlen(argv[1])+3);
                strcpy(temp_file_name, argv[1]);
                strcat(temp_file_name, ".uf");

                fptr_write = fopen(temp_file_name, "rb");

                if(fptr_write) {
                    printf("[ERROR]: %s file already exists, exiting with error code (33)\n", temp_file_name);
                    fclose(fptr_write);
                    exit(33);
                }

                fptr_write = fopen(temp_file_name, "wb");


                fwrite(enc->cipher_text, 1, payload_len, fptr_write);
                fwrite(&enc->iv, 1, IV_LEN, fptr_write);	
                fwrite(enc->salt, 1, SALT_LEN, fptr_write);
                fwrite(enc->hmac, 1, HASH_SZ, fptr_write);

                int written_size = (f_size + IV_LEN + SALT_LEN + HASH_SZ);
                printf("Successfully encrypted %s to %s.uf  ( %u bytes written) \n", 
                        argv[1], argv[1], written_size);

                fclose(fptr_write);

                FREE(temp_file_name);


            }
            break;
    };

    /*
     * Free allocated memory buffers and exit *
     */
    deinit(enc);

    /*
     * Close source file
     */
    fclose(fptr_read);

    return 0;
}
