#include "common.h"


char*                                                                                                                                                                  
generate_passkey()                                                                                                                                                      
{                                                                                                                                                                       
    char password[32];                                                                                                                                                  
    char key_buffer[16];                                                                                                                                                
                                                                                                                                                                        
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
                                                                                                                                                                        
    printf("Key: %X \n", key_buffer);                                                                                                                                   
                                                                                                                                                                        
    return key_buffer;                                                                                                                                                  
}
