#include "common.h"


#define CHECK_GCRY_ERROR(ret_val, func_call) {\
    if(ret_val) {\
	printf("ERROR [%s: %d] Call to %s Failed..\n", __FUNCTION__,__LINE__, func_call);\
	return NULL;\
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
                                                                                                                                                                        
    memset(key_buffer, '\0', KEY_LEN);                                                                                                                       

    gcry_kdf_derive(password,                                                                                                                                           
                    strlen(password),                                                                                                                                   
                    GCRY_KDF_PBKDF2,                                                                                                                                    
                    GCRY_MD_SHA512,                                                                                                                                     
                    SALT,                                                                                                                                             
                    SALT_LEN,                                                                                                                                     
                    ITERATIONS,
                    KEY_LEN,                                                                                                                                 
                    key_buffer);                                                                                                                                        
          
    unsigned char *ptr = key_buffer;
    int i = 0;

    printf("Key: ");
    while(i < KEY_LEN) {
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
    gcry_error_t gcry_err;

    unsigned long int iv = IV;
    size_t key_len;
    size_t block_len;
    size_t plain_txt_len;
    char   *cipher_text = (char *) malloc(send_buff_len);

    gcry_cipher_hd_t handle;

    key_len = gcry_cipher_get_algo_keylen(ENCRYPTION_ALGO);
    
    block_len = gcry_cipher_get_algo_blklen(ENCRYPTION_MODE);

    plain_txt_len = send_buff_len;

    gcry_err = gcry_cipher_open(&handle, ENCRYPTION_ALGO, ENCRYPTION_MODE, GCRY_CIPHER_CBC_CTS);
    CHECK_GCRY_ERROR(gcry_err, "gcry_cipher_open");

    gcry_err = gcry_cipher_setkey(handle, key, key_len);
    CHECK_GCRY_ERROR(gcry_err, "gcry_cipher_setkey");

    gcry_err = gcry_cipher_setiv(handle, &iv, block_len);
    CHECK_GCRY_ERROR(gcry_err, "gcry_cipher_setiv");

    gcry_err = gcry_cipher_encrypt(handle, cipher_text, send_buff_len, send_buffer, plain_txt_len);
    CHECK_GCRY_ERROR(gcry_err, "gcry_cipher_encrypt");

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
		  char *key,
		  int  f_size)
{
    int read_bytes;

    while(!feof(fptr)) {
	read_bytes = fread(send_buffer, f_size, 1, fptr);

	if(read_bytes < 0) {
	    printf("File Read Failed\n");
	    return NULL;
	}
    }

    return _encrypt(send_buffer, key, f_size);
}


char*
_hmac(char *cipher,
      char *key,
      int  f_size)
{
    gcry_error_t gcry_err;

    unsigned char   *hash_val = NULL;
    char   *computed_hash = (char *) malloc (HASH_SZ);

    gcry_md_hd_t handle;

    gcry_err = gcry_md_open(&handle, HASH_ALGO, GCRY_MD_FLAG_HMAC);
    CHECK_GCRY_ERROR(gcry_err, "gcry_md_open");

    gcry_err = gcry_md_enable(handle, HASH_ALGO);
    CHECK_GCRY_ERROR(gcry_err, "gcry_md_enable");

    gcry_err = gcry_md_setkey(handle, key, KEY_LEN);
    CHECK_GCRY_ERROR(gcry_err, "gcry_md_setkey");

    gcry_md_write(handle, cipher, sizeof(cipher));

    hash_val = gcry_md_read(handle, HASH_ALGO);

    if(NULL == hash_val) {
	return NULL;
    }

    memcpy(computed_hash, hash_val, HASH_SZ);

    gcry_md_close(handle);

    return computed_hash;
}
char*
generate_hmac(char *cipher,
	      char *key,
	      int  f_size)
{
    return _hmac(cipher, key, f_size);
}


char*
decrypt_file_data(FILE *fptr,
		  char *key)
{
    int f_size;
    int read_bytes;

    f_size = get_file_size(fptr);

    while(!feof(fptr)) {
	read_bytes = fread(send_buffer, f_size, 1, fptr);

	if(read_bytes < 0) {
	    printf("File Read Failed\n");
	    return NULL;
	}
    }

    char *cipher_text = _encrypt(send_buffer, key, f_size);

    if(!cipher_text) {
	printf("Encryption Failed\n");
	return NULL;
    }

    return cipher_text;
}
