#include "common.h"


#define CHECK_GCRY_ERROR(ret_val, func_call) {\
    if(ret_val) {\
	printf("ERROR [%s: %d] Call to %s Failed..\n", __FUNCTION__,__LINE__, func_call);\
	return FAILURE;\
    }\
}

int get_file_size(FILE *fptr)
{
    int size = 0;

    fseek(fptr, 0, SEEK_END);
    size = ftell(fptr);
    rewind(fptr);

    return size;
}

void 
generate_passkey(Enc_Dec_Apparatus_t *enc)                                                                                                                                                      
{                                                                                                                                                                       
    char password[MAX_PASSWORD_LEN];
    
    enc->key = (char *) malloc(sizeof(char) * KEY_LEN); 

    enc->salt = (char *) malloc(sizeof(char) * SALT_LEN);
    strcpy(enc->salt, SALT);
                                                                                                                                                                        
    printf("Password : ");                                                                                                                                              
    scanf("%s", password);                                                                                                                                              
                                                                                                                                                                        
    gcry_check_version(NULL);                                                                                                                                           
                                                                                                                                                                        
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


Error_t  _encrypt(Enc_Dec_Apparatus_t *enc, 
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

Error_t
encrypt_file_data(FILE *fptr,
		  Enc_Dec_Apparatus_t *enc,
		  int  f_size)
{
    int read_bytes;

    while(!feof(fptr)) {
	read_bytes = fread(enc->send_buffer, f_size, 1, fptr);

	if(read_bytes < 0) {
	    printf("File Read Failed\n");
	    return FAILURE;
	}
    }

    return _encrypt(enc, f_size);
}


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

    gcry_md_write(handle, eda->cipher_text, strlen(eda->cipher_text));

    hash_val = gcry_md_read(handle, HASH_ALGO);

    memcpy(eda->hmac, hash_val, HASH_SZ);

    if(NULL == eda->hmac) {
	return HMAC_FAIL;
    }

    gcry_md_close(handle);

    return SUCCESS;
}
Error_t
generate_hmac(Enc_Dec_Apparatus_t *enc,
	      int  f_size)
{
    return _hmac(enc, f_size);
}
char*
remove_hmac(char *file_name)
{
    FILE *fptr = fopen(file_name, "r+");

    fseek(fptr, (4 + 16), SEEK_SET);

    char hmac = (char *) malloc(HASH_SZ);

    fread(hmac, 1, HASH_SZ, fptr);

    fclose(fptr);

    return hmac;
}

Error_t
_verify_hmac(Enc_Dec_Apparatus_t *dec,
	    char *rcvd_hmac,
	    int  f_size)
{
     int ret = _hmac(dec, f_size);

     if(SUCCESS != ret) {
	 return HMAC_FAIL;
     }

     return memcmp(dec->hmac, rcvd_hmac, HASH_SZ);
}


Error_t
verify_hmac(char *file_name,
	    Enc_Dec_Apparatus_t *dec)
{
    int f_size;
    int read_bytes;

    FILE *fptr = fopen(file_name, "r+");
    f_size = get_file_size(fptr);
    fclose(fptr);


    fptr = fopen(file_name, "r+");

    int payload_size = f_size - (IV_LEN + SALT_LEN + HASH_SZ);
    dec->cipher_text = (char *) malloc(payload_size);
    read_bytes = fread(dec->cipher_text, payload_size, 1, fptr);

    if(read_bytes < 0) {
	printf("File Read Failed while reading ciphertext\n");
	return FAILURE;
    }

    printf("Read %d bytes \n", read_bytes);

    fread(&dec->iv, 1, IV_LEN, fptr);
    printf("Got IV  \n");

    dec->salt = (char *) malloc (SALT_LEN);
    fread(dec->salt, 1, SALT_LEN, fptr);
    printf("Got SALT  \n");


    char *rcvd_hmac = (char *) malloc(HASH_SZ);
    read_bytes = fread(rcvd_hmac, HASH_SZ, 1, fptr);

    printf("HMAC verification \n");

    int h = _verify_hmac(dec, rcvd_hmac, f_size);

    fclose(fptr);

    return h;;
}

Error_t
_decrypt(int f_size,
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

    gcry_err = gcry_cipher_decrypt(handle, plain_text, plain_txt_len, dec->cipher_text, strlen(dec->cipher_text));
    CHECK_GCRY_ERROR(gcry_err, "(Decryption) gcry_cipher_decrypt");

    gcry_cipher_close(handle);

    puts(plain_text);

    return SUCCESS;
}
Error_t
decrypt_file_data(char *file_name,
	    	  Enc_Dec_Apparatus_t *dec)
{

    FILE *fptr = fopen(file_name, "r+");
    int f_size = get_file_size(fptr);
    fclose(fptr);

    return _decrypt(f_size, dec);
    
}
