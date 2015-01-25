/************************************************************************************                                                                           
*  A Secure copy tool for local and remote copy                                     *                                                                           
*                                                                                   *                                                                           
*  http://cise.ufl.edu/class/cnt5410fa14/hw/hw2.html                                *                                                                           
*                                                                                   *                                                                           
*  Author: Yogesh Patil (ypatil@cise.ufl.edu)                                       *                                                                           
************************************************************************************/

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include "common.h"

/*
 *   Utility function that prints the 'how to use'
 */
void how_to_use() 
{
    printf("gatordec <input file> [-d < port >][-l] \n\n");
    printf("Description: \n\n");
    printf(" -d < port > :\n");
    printf("     Listening port \n");
    printf(" -l :\n");
    printf("     Local Mode: decode local file \n");
}

/*
 *   Utility function that prints the 'how to use'
 */
Error_t
receive_remote_data(int   conn_fd, 
		    Enc_Dec_Apparatus_t  *dec,
		    FILE  *write_fptr)
{
    int rcvd_bytes = 0;

    dec->recv_buffer = (char *) malloc(BUFFER_SIZE);
    memset(dec->recv_buffer, '\0', BUFFER_SIZE);
    rcvd_bytes = recv(conn_fd, dec->recv_buffer, BUFFER_SIZE, 0);

    if(rcvd_bytes == -1) {
        return RECV_FAIL;
    }
    fwrite(dec->recv_buffer, 1, rcvd_bytes, write_fptr);
    fflush(write_fptr);

    while(rcvd_bytes > 0) {

        memset(dec->recv_buffer, '\0', BUFFER_SIZE);
        rcvd_bytes = recv(conn_fd, dec->recv_buffer, BUFFER_SIZE, 0);


        if(rcvd_bytes > 0)
            fwrite(dec->recv_buffer, 1, rcvd_bytes, write_fptr);
        fflush(write_fptr);
    }


    return SUCCESS;
}

/*
 * Creata a listening socket and wait for incoming connections
 * As connect request is seen, accpept the connection  
 */
Error_t
wait_for_incoming_connection(Enc_Dec_Apparatus_t *dec,
			     int server_port, 
			     int  *conn_fd)
{
    Error_t ret_status = SUCCESS;

    int sock_len = 0;
    int read_bytes = 0;

    struct sockaddr_in client_addr;
    struct sockaddr_in server_addr;

    /* Create listening socket */
    dec->sock_id = socket(AF_INET, SOCK_STREAM, 0);

    if(dec->sock_id < 0) {

        printf("\n Error opening socket");
        return SOCKET_FAIL;
    }

    memset(&server_addr, '0', sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(server_port);

    /* 
     * Bind the local machines IP address and user provided Port number
     * to created socket
     */
    ret_status = bind( dec->sock_id, 
            (struct sockaddr *) &server_addr, 
            sizeof(server_addr));

    if(ret_status < 0) {

        printf("\n Error binding socket");
        return BIND_FAIL;
    }

    /* Listen for incoming connections */
    ret_status = listen(dec->sock_id, 10);

    if(ret_status < 0) {

        printf("listen Failed \n");
        return LISTEN_FAIL;
    }
    printf(" Waiting for connections \n");

    sock_len = sizeof(struct sockaddr_in);

    /* 
     * Accept incoming connection 
     * Returning conn_fd as output parameter to be used for 
     * subsequent Send and Recv operations
     */
    *conn_fd = accept( dec->sock_id, 
            (struct sockaddr *) &client_addr, 
            (socklen_t *) &sock_len);

    if(*conn_fd < 0) {
        printf(" ERROR: accept failed \n");
        return ACCEPT_FAIL;
    }

    printf(" Inbound File \n");

    return SUCCESS;
}


/*
 *   main method for decryption
 */
int main(int argc, char *argv[])
{
    Error_t	ret_status = SUCCESS;
    Mode_t  	mode = UNDEFINED;

    int		bad_options = FALSE;

    /*
     * Check if sufficient arguments are provided 
     */
    if(argc < 3) {
        printf("ERROR: Insufficient/Incorrect Arguments\n");
        how_to_use();
        return FAILURE;
    }

    /*
     * Check if this is decryption from a remote machines
     */
    if(!strcmp("-d", argv[2])) 
    {
        if(argc < 4) { 
            bad_options = TRUE;
        }

        mode = REMOTE;
    }

    /*
     * Check if this is decryption from a local machines
     */
    else if(!strcmp("-l", argv[2])) 
    {
        mode = LOCAL;
    }

    /*
     * If you're here you must have provided wrong arguments
     * report an error and exit
     */
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

    /*
     * Initialize encrption and decryption apparatus
     */
    ret_status = init(&dec);

    if(SUCCESS != ret_status) {
        printf("Failed to allocate memory \n");
        exit(1);
    }

    switch(mode) {

        case REMOTE:
            /*
             * If this is copy from remote machines, listen for incoming connections
             * and receive using data socket
             */
            {
                int server_port = atoi(argv[3]);
                int conn_fd = 0;

                char *temp_file_name = (char *) malloc (strlen(argv[1])+3);
                strcpy(temp_file_name, argv[1]);
                strcat(temp_file_name, ".uf");

                FILE *f1 = fopen(temp_file_name, "rb");
                if(f1) {
                    printf("[ERROR]: %s file already exists, exiting with error code (33)\n", temp_file_name);
                    fclose(f1);
                    exit(33);
                }

                write_fptr = fopen(temp_file_name, "wb");

                if(NULL == write_fptr) {

                    printf("ERROR: Error while opening input file %s, please check if file exists\n", argv[1]); 
                    return FOPEN_FAIL;
                }

                /*
                 * wait for incoming connections
                 * and accept once available
                 */
                ret_status = wait_for_incoming_connection(dec, server_port, &conn_fd);

                if(SUCCESS != ret_status) {
                    printf("No Incoming Connection\n");
                    return RECV_FAIL;
                }

                /*
                 * Receive data from remote machines
                 */
                ret_status = receive_remote_data(conn_fd, dec, write_fptr);

                /*
                 * Write Receive data to some local file
                 * and close the opened connections and file
                 */
                close(conn_fd);
                close(dec->sock_id);
                fclose(write_fptr);

                if(SUCCESS != ret_status) {
                    printf("Receive Failed\n");
                    return RECV_FAIL;
                }

                /*
                 * Retrive cryptographic information from received file.
                 * This is needed for decryption
                 */
                ret_status = retrieve_cryto_params(temp_file_name, dec);

                if(SUCCESS != ret_status) {
                    printf("failed to retirive security parameters ....exiting with error code (1)\n");
                    exit(1);
                }

                /*
                 * Ask for password to decrypt the file
                 */
                generate_passkey(dec);

                if(NULL == dec->key) {
                    printf("Key generation Failed....exiting with 1");
                    exit(1);
                }

                /*
                 * First compute the HMAC for received data and verify it with received HMAC
                 * to make sure integrity of received data
                 */
                ret_status = verify_hmac(temp_file_name, dec);

                if(SUCCESS != ret_status) {
                    printf("HMAC verification failed....exiting with error code (62) \n");
                    exit(62);
                }
                else {

#if DEBUG
                    printf("HMAC verification Success\n");
#endif
                }

                /*
                 * Once HMAC verification is successful, you can go ahead and decrypt the file
                 */
                ret_status = decrypt_file_data(temp_file_name, argv[1], dec);

                if(SUCCESS != ret_status) {
                    printf("Decryption failed ....exiting with error code (1)\n");
                    exit(1);
                }

                printf("Successfully received and decrypted %s ( %u bytes written) \n",
                        argv[1], dec->plain_text_len);

                FREE(temp_file_name);

                remove(temp_file_name);

            }
            break;

        case LOCAL:
            /*
             * If this is copy from local machine, open source file 
             * and write decrypted data to corresponding file
             */
            {
                char *temp_file_name = (char *) malloc (strlen(argv[1]) - 3);
                strncpy(temp_file_name, argv[1], strlen(argv[1]) - 3);

                FILE *f1 = fopen(temp_file_name, "rb");
                if(f1) {
                    printf("[ERROR]: %s file already exists, exiting with error code (33)\n", temp_file_name);
                    fclose(f1);
                    exit(33);
                }

                FILE *fptr = fopen(argv[1], "rb");

                if(NULL == fptr) {
                    printf("File to decrypt does not exist....exiting with error code (1) \n");
                    exit(1);
                } 
                else {
                    fclose(fptr);
                }

                /*
                 * Retrive cryptographic information from source file.
                 * This is needed for decryption
                 */
                ret_status = retrieve_cryto_params(argv[1], dec);

                if(SUCCESS != ret_status) {
                    printf("failed to retirive security parameters ....exiting with error code (1)\n");
                    exit(1);
                }

                /*
                 * Ask for password to decrypt the file
                 */
                generate_passkey(dec);

                if(NULL == dec->key) {
                    printf("Key generation Failed....exiting with 1");
                    exit(1);
                }

                /*
                 * First compute the HMAC for source file data and verify it with appended HMAC
                 * to make sure integrity of received data
                 */
                ret_status = verify_hmac(argv[1], dec);

                if(SUCCESS != ret_status) {
                    printf("HMAC verification failed....exiting with error code (1) \n");
                    exit(1);
                }
                else {
                    printf("HMAC verification Success\n");
                }

                /* 
                 * Once HMAC verification is successful, you can go ahead and decrypt the file
                 */
                ret_status = decrypt_file_data(argv[1], temp_file_name,  dec);

                if(SUCCESS != ret_status) {
                    printf("Decryption failed ....exiting with error code (1)\n");
                    exit(1);
                }
                else {
                    printf("Successfully decrypted %s ( %u bytes written) \n",
                        argv[1], dec->plain_text_len);
                }

                FREE(temp_file_name);
            }


            break;
    };


    /*
     * Free allocated memory buffers and exit 
     */
    deinit(dec);

    return SUCCESS;
}
