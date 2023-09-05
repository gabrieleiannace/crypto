//  Exercise 1.3. Writes a program in C that, using the OpenSSL library, randomly generates the private
//  key to be used for encrypting data with AES128 in CBC mode and the IV.
//  Pay attention to selecting the proper PRNG for both the “private” key and IV

#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MAX 16

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char *argv[]){
    
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();
    
    unsigned char key[MAX];
    unsigned char iv[MAX];

    if(RAND_load_file("/dev/random", MAX) != MAX)
        handle_errors();

    if(!RAND_bytes(key,MAX))
        handle_errors();

    if(!RAND_bytes(iv,MAX))
        handle_errors();

    printf("%s\n", key);
    printf("%s\n", iv);

    unsigned char plaintext[] = "This is the plaintext to encrypt.";
    unsigned char ciphertext[MAX];
    int ciphertext_len = 0, len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT);

    EVP_CipherUpdate(ctx, ciphertext, &len, plaintext, strlen(plaintext));
    ciphertext_len+=len;
    EVP_CipherFinal(ctx, ciphertext+len, &len);
    ciphertext_len+=len;

    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);


    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
    
    return 0;
}