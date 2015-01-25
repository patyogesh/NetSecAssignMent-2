/************************************************************************************                                                                           
*  A Secure copy tool for local and remote copy                                     *                                                                           
*                                                                                   *                                                                           
*  http://cise.ufl.edu/class/cnt5410fa14/hw/hw2.html                                *                                                                           
*                                                                                   *                                                                           
*  Author: Yogesh Patil (ypatil@cise.ufl.edu)                                       *                                                                           
************************************************************************************/


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

/*
 * Macros for some constants
 */
#define TRUE 1
#define FALSE 0

#define BUFFER_SIZE 1024
#define SERVER_PORT 2346

/*
 * constants for key generation
 */
#define MAX_PASSWORD_LEN 32
#define KEY_LEN 64
#define ITERATIONS 4096
#define SALT "NaCl"
#define SALT_LEN strlen(SALT)

/*
 * constants for Encryption and Decryption
 */
#define IV 5844
#define IV_LEN 8
#define IV_SIZE sizeof(IV)
#define ENCRYPTION_ALGO GCRY_CIPHER_AES128
#define ENCRYPTION_MODE GCRY_CIPHER_MODE_CBC

#define HASH_ALGO GCRY_MD_SHA512
#define HASH_SZ 64

/*
 * Secure copy can work in two modes
 * LOCAL: On same machine
 * REMOTE: From one machine to another machines
 */
typedef enum mode {
    REMOTE,
    LOCAL,
    UNDEFINED
}
Mode_t;

/*
 * Enum defining various errors
 */
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
    
    HMAC_FAIL,
    UNEXPECTED
} 
Error_t;

/*
 * This structure is a container providing apparatus
 * for encryption and decryption
 */
typedef struct enc_dec_apparatus
{
    int  sock_id;   /* socket descriptor */

    char *key;      /* Hash Key */
    char *salt;     /* salt for key generation */
    char *cipher_text; /* Cipher text generated  after encryption */
    char *hmac;     /* computed hmac */
    
    unsigned long int iv;   /* Initialization vector (Integer) */
    
    char *send_buffer;  /* pointer to buffer to be sent to remote machines */
    char *recv_buffer;  /* pointer to buffer to receive from remote machines */

    int  plain_text_len;    /* length of plain text after decryption */
}
Enc_Dec_Apparatus_t;

/*
 * Function prototypes
 */
void generate_passkey(Enc_Dec_Apparatus_t *eda);

Error_t encrypt_file_data(FILE *fptr, 
			  Enc_Dec_Apparatus_t *enc, 
			  int file_size);
Error_t generate_hmac(Enc_Dec_Apparatus_t *eda,
		      int  f_size);

/*
 * Macro to free buffers
 */
#define FREE(b) {\
    if(b) {\
	free(b);\
	b = NULL;\
    }\
}

#endif
