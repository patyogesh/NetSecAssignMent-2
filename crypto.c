/************************************************************************************
*  A Secure copy tool for local and remote copy                                     *
*                                                                                   *
*  http://cise.ufl.edu/class/cnt5410fa14/hw/hw2.html                                *
*                                                                                   *
*  Author: Yogesh Patil (ypatil@cise.ufl.edu)                                       *
************************************************************************************/


#include "common.h"


/*
 * macro that checks if error occured, reports it and 
 * return FAILURE
 */
#define CHECK_GCRY_ERROR(ret_val, func_call) {\
    if(ret_val) {\
	printf("ERROR [%s: %d] Call to %s Failed..\n", __FUNCTION__,__LINE__, func_call);\
	return FAILURE;\
    }\
}

/*
 * Allocates/Initializes memory for Enc_Dec_Apparatus_t
 */
Error_t
init(Enc_Dec_Apparatus_t **eda)
{
    *eda = (Enc_Dec_Apparatus_t *) malloc(sizeof(Enc_Dec_Apparatus_t));
    
    if(*eda) {
	    return SUCCESS;
    }

    return FAILURE;
}

/*
 * Frees various buffers 
 */
void
deinit(Enc_Dec_Apparatus_t *eda)
{
    FREE(eda->send_buffer);
    FREE(eda->recv_buffer);
    FREE(eda->key);
    FREE(eda->salt);
    FREE(eda->cipher_text);
    FREE(eda->hmac);
    FREE(eda);
}

/*
 * A utility function that returns file size
 */
int get_file_size(FILE *fptr)
{
    int size = 0;

    fseek(fptr, 0, SEEK_END);
    size = ftell(fptr);
    rewind(fptr);

    return size;
}

/*
 * This function takes user password and input
 * Comutes HASH key for a password
 */
void 
generate_passkey(Enc_Dec_Apparatus_t *enc)
{
    char password[MAX_PASSWORD_LEN];
    
    printf("Password : ");                                                                                                                                              
    scanf("%s", password);                                                                                                                                              
    gcry_check_version(NULL);                                                                                                                                           
    enc->key = (char *) malloc(sizeof(char) * KEY_LEN); 
    memset(enc->key, '\0', KEY_LEN);                                                                                                                       

    gcry_kdf_derive(password,                                                                                                                                           
                    strlen(password),                                                                                                                                   
                    GCRY_KDF_PBKDF2,                                                                                                                                    
                    GCRY_MD_SHA512,
		            enc->salt,
		            SALT_LEN,
                    ITERATIONS,
                    KEY_LEN,                                                                                                                                 
                    enc->key);                                                                                                                                        
          
    unsigned char *ptr = enc->key;
    int i = 0;

    printf("Key: ");
    while(i < KEY_LEN) {
        printf("%X ", *ptr);
        ptr++;
        i++;
    }
    printf("\n");
}


/*
 * This is core encryption function that converts
 * plain text to cipher text
 */
Error_t  
_encrypt(Enc_Dec_Apparatus_t *enc, 
	     	int  send_buff_len)
{
    gcry_error_t gcry_err;

    size_t key_len;
    size_t block_len;
    size_t plain_txt_len;

    enc->cipher_text = (char *) malloc(send_buff_len);

    gcry_cipher_hd_t handle;

    key_len = gcry_cipher_get_algo_keylen(ENCRYPTION_ALGO);
    
    block_len = gcry_cipher_get_algo_blklen(ENCRYPTION_MODE);

    plain_txt_len = send_buff_len;

    gcry_err = gcry_cipher_open(&handle, ENCRYPTION_ALGO, ENCRYPTION_MODE, GCRY_CIPHER_CBC_CTS);
    CHECK_GCRY_ERROR(gcry_err, "(Encyption) gcry_cipher_open");

    gcry_err = gcry_cipher_setkey(handle, enc->key, key_len);
    CHECK_GCRY_ERROR(gcry_err, "(Encyption) gcry_cipher_setkey");

    enc->iv = IV;
    gcry_err = gcry_cipher_setiv(handle, &enc->iv, block_len);
    CHECK_GCRY_ERROR(gcry_err, "(Encyption) gcry_cipher_setiv");

    gcry_err = gcry_cipher_encrypt(handle, enc->cipher_text, send_buff_len, enc->send_buffer, plain_txt_len);
    CHECK_GCRY_ERROR(gcry_err, "(Encyption) gcry_cipher_encrypt");

    gcry_cipher_close(handle);

    return SUCCESS;
}

/*
 * Wrapper function for encryption
 */
Error_t
encrypt_file_data(FILE *fptr,
		  Enc_Dec_Apparatus_t *enc,
		  int  f_size)
{
    int read_bytes;

    enc->send_buffer = (char *) malloc (f_size);

    while(!feof(fptr)) {
        read_bytes = fread(enc->send_buffer, f_size, 1, fptr);

        if(read_bytes < 0) {
            printf("File Read Failed\n");
            return FAILURE;
        }
    }

    return _encrypt(enc, f_size);
}


/*
 * core function that computes HMAC for 
 */
Error_t
_hmac(Enc_Dec_Apparatus_t *eda,
      int  f_size)
{
    gcry_error_t gcry_err;

    unsigned char   *hash_val = NULL;
    eda->hmac = (char *) malloc (HASH_SZ);

    gcry_md_hd_t handle;

    gcry_err = gcry_md_open(&handle, HASH_ALGO, GCRY_MD_FLAG_HMAC);
    CHECK_GCRY_ERROR(gcry_err, "gcry_md_open");

    gcry_err = gcry_md_enable(handle, HASH_ALGO);
    CHECK_GCRY_ERROR(gcry_err, "gcry_md_enable");

    gcry_err = gcry_md_setkey(handle, eda->key, KEY_LEN);
    CHECK_GCRY_ERROR(gcry_err, "gcry_md_setkey");

    gcry_md_write(handle, eda->cipher_text, f_size);

    hash_val = gcry_md_read(handle, HASH_ALGO);

    memcpy(eda->hmac, hash_val, HASH_SZ);

    if(NULL == eda->hmac) {
        return HMAC_FAIL;
    }

    gcry_md_close(handle);

    return SUCCESS;
}
/*
 * Wrapper function for HMAC computation
 * Call after encryption
 */
Error_t
generate_hmac(Enc_Dec_Apparatus_t *enc,
	      int  f_size)
{
    return _hmac(enc, f_size);
}

/*
 * Wrapper function to verify HMAC
 * To be called before decryption
 */
Error_t
_verify_hmac(Enc_Dec_Apparatus_t *dec,
	    char *rcvd_hmac,
	    int  f_size)
{
    int ret = _hmac(dec, (f_size - (IV_LEN + SALT_LEN + HASH_SZ)));

    if(SUCCESS != ret) {
        return HMAC_FAIL;
    }

    return memcmp(dec->hmac, rcvd_hmac, HASH_SZ);
}

/*
 * Generic utility  function that derives the cryptographic information
 * from file to be decrypted
 */
Error_t
retrieve_cryto_params(char *file_name,
	                  Enc_Dec_Apparatus_t *dec)
{
    int f_size;
    int read_bytes;

    FILE *fptr = fopen(file_name, "rb");

    f_size = get_file_size(fptr);
    fclose(fptr);


    fptr = fopen(file_name, "rb");

    /* Read Ciphertext */
    int payload_size = f_size - (IV_LEN + SALT_LEN + HASH_SZ);
    dec->cipher_text = (char *) malloc(payload_size);
    read_bytes = fread(dec->cipher_text, payload_size, 1, fptr);

    if(read_bytes < 0) {
        printf("File Read Failed while reading ciphertext\n");
        fclose(fptr);
        return FAILURE;
    }

    /* Read IV */
    fseek(fptr, payload_size, SEEK_SET);
    read_bytes = fread(&dec->iv, 1, IV_LEN, fptr);

    if(read_bytes < 0) {
        printf("File Read Failed while reading IV\n");
        fclose(fptr);
        return FAILURE;
    }

    /* Read SALT */
    fseek(fptr, (payload_size + IV_LEN), SEEK_SET);
    dec->salt = (char *) malloc (SALT_LEN);
    read_bytes = fread(dec->salt, 1, SALT_LEN, fptr);

    if(read_bytes < 0) {
        printf("File Read Failed while reading SALT\n");
        fclose(fptr);
        return FAILURE;
    }

    /* Read HMAC finally at the time of HMAC verification */
    fclose(fptr);
    return SUCCESS;
}

/*
 * Wrapper function to verify HMAC
 * To be called before decryption
 */
Error_t
verify_hmac(char *file_name,
	    Enc_Dec_Apparatus_t *dec)
{
    int f_size;
    int read_bytes;

    FILE *fptr = fopen(file_name, "rb");
    
    f_size = get_file_size(fptr);
    fclose(fptr);

    int payload_size = f_size - (IV_LEN + SALT_LEN + HASH_SZ);
    fptr = fopen(file_name, "rb");
    
    fseek(fptr, (payload_size + IV_LEN + SALT_LEN), SEEK_SET);
    
    char *rcvd_hmac = (char *) malloc(HASH_SZ);

    read_bytes = fread(rcvd_hmac, HASH_SZ, 1, fptr);

    int h = _verify_hmac(dec, rcvd_hmac, f_size);

    fclose(fptr);

    return h;;
}

/*
 * core decryption function
 */
Error_t
_decrypt(char* file_name,
	 int f_size,
	 Enc_Dec_Apparatus_t *dec)
{
    gcry_error_t gcry_err;

    size_t  key_len;
    size_t  block_len;

    int payload_len = (f_size - (IV_LEN + SALT_LEN + HASH_SZ));
    size_t  plain_txt_len = payload_len;

    char*   plain_text = (char *) malloc (plain_txt_len);

    gcry_cipher_hd_t handle;

    key_len = gcry_cipher_get_algo_keylen(ENCRYPTION_ALGO);

    block_len = gcry_cipher_get_algo_blklen(ENCRYPTION_MODE);

    gcry_err = gcry_cipher_open(&handle, ENCRYPTION_ALGO, ENCRYPTION_MODE, GCRY_CIPHER_CBC_CTS);
    CHECK_GCRY_ERROR(gcry_err, "(Decryption) gcry_cipher_open");

    gcry_err = gcry_cipher_setkey(handle, dec->key, key_len);
    CHECK_GCRY_ERROR(gcry_err, "(Decryption) gcry_cipher_setkey");

    gcry_err = gcry_cipher_setiv(handle, &dec->iv, block_len);
    CHECK_GCRY_ERROR(gcry_err, "(Decryption) gcry_cipher_setiv");

    gcry_err = gcry_cipher_decrypt(handle, plain_text, plain_txt_len, dec->cipher_text, payload_len);
    CHECK_GCRY_ERROR(gcry_err, "(Decryption) gcry_cipher_decrypt");

    gcry_cipher_close(handle);


    // FIX ME- DONE
    FILE *fptr = fopen(file_name, "wb");

    if(!fptr) {
        printf("Error while writing to file during decryption....existing with error code (1) \n");
        exit(1);
    }

    fwrite(plain_text, 1, payload_len, fptr);

    dec->plain_text_len = plain_txt_len;

    fclose(fptr);

    return SUCCESS;
}

/*
 * wrapper function to decrypt the file 
 */
Error_t
decrypt_file_data(char *input_file_name,
		  char *output_file_name,
	    	  Enc_Dec_Apparatus_t *dec)
{

    FILE *fptr = fopen(input_file_name, "rb");

    if(NULL == fptr) {
        return FOPEN_FAIL;
    }

    int f_size = get_file_size(fptr);
    fclose(fptr);

    return _decrypt(output_file_name, f_size, dec);

}
