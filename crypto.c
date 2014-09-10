#include "common.h"


#define CHECK_GCRY_ERROR(ret_val) {\
    if(ret_val) {\
	printf("%s Failed. Exiting with 1", __FUNCTION__);\
	exit(1);\
    }\
}

char*                                                                                                                                                                  
generate_passkey()                                                                                                                                                      
{                                                                                                                                                                       
    char password[MAX_PASSWORD_LEN];
    char *key_buffer = (char *) malloc(sizeof(char) * KEY_LEN); 
                                                                                                                                                                        
    printf("Password : ");                                                                                                                                              
    scanf("%s", password);                                                                                                                                              
                                                                                                                                                                        
    gcry_check_version(NULL);                                                                                                                                           
                                                                                                                                                                        
    memset(key_buffer, '\0', sizeof(key_buffer));                                                                                                                       

    gcry_kdf_derive(password,                                                                                                                                           
                    strlen(password),                                                                                                                                   
                    GCRY_KDF_PBKDF2,                                                                                                                                    
                    GCRY_MD_SHA512,                                                                                                                                     
                    "NaCl",                                                                                                                                             
                    strlen("NaCl"),                                                                                                                                     
                    4096,                                                                                                                                               
                    sizeof(key_buffer),                                                                                                                                 
                    key_buffer);                                                                                                                                        
          
    unsigned char *ptr = key_buffer;
    int i = 0;

    printf("Key: ");
    while(i < sizeof(key_buffer)) {
	printf("%X ", *ptr);
	ptr++;
	i++;
    }
    printf("\n");
    return key_buffer;                                                                                                                                                  
}


char*  _encrypt(char *send_buffer, 
	     	char *key, 
	     	int  send_buff_len)
{
    int ret_status = SUCCESS;
    gcry_error_t gcry_err;

    int    iv = IV;
    size_t key_len;
    size_t block_len;
    size_t plain_txt_len;
    char   *cipher_text;

    gcry_cipher_hd_t handle;

    key_len = gcry_cipher_get_algo_keylen(ENCRYPTION_ALGO);
    block_len = gcry_cipher_get_algo_blklen(ENCRYPTION_MODE);
    plain_txt_len = send_buff_len;

    cipher_text = (char *) malloc(sizeof(send_buff_len));

    gcry_err = gcry_cipher_open(&handle, ENCRYPTION_ALGO, ENCRYPTION_MODE, 0);
    CHECK_GCRY_ERROR(gcry_err);

    gcry_err = gcry_cipher_setkey(handle, key, key_len);
    CHECK_GCRY_ERROR(gcry_err);

    gcry_err = gcry_cipher_setiv(handle, &iv, block_len);
    CHECK_GCRY_ERROR(gcry_err);

    gcry_err = gcry_cipher_encrypt(handle, cipher_text, send_buff_len, send_buffer, send_buff_len);
    CHECK_GCRY_ERROR(gcry_err);

    gcry_cipher_close(handle);

    return cipher_text;
}

int get_file_size(FILE *fptr)
{
    int size = 0;

    fseek(fptr, 0, SEEK_END);
    size = ftell(fptr);
    rewind(fptr);

    return size;
}
char*
encrypt_file_data(FILE *fptr,
		  char *key)
{
    int f_size;
    int read_bytes;

    f_size = get_file_size(fptr);

    while(!feof(fptr)) {
	read_bytes = fread(send_buffer, BUFFER_SIZE, 1, fptr);

	if(read_bytes < 0) {
	    printf("File Read Failed\n");
	    return NULL;
	}
    }

    char * cipher_text = _encrypt(send_buffer, key, f_size);

    if(cipher_text) {
	printf("Encryption Failed\n");
	return NULL;
    }

    return cipher_text;
}
