// EVP_get_cipherbyname

// Exercise 2.1. Write a program in C that, using the OpenSSL library, encrypts the content of a file
// using a user-selected algorithm. The filename is passed as the first parameter from the command line,
// and the algorithm is passed as the second parameter and must be an OpenSSL-compliant string (e.g.,
// aes-128-cbc or aes-256-ecb).

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0
#define MAX_SIZE 1024

int main(int argc, char *argv[]){
    
    if(argc != 3){
        fprintf(stderr, "Error using the tool. Usage: %s [file_name] [algorithm]\n", argv[0]);
        abort();
    }

    FILE *f_in = fopen(argv[1], "r");
    int n_read;
    unsigned char buffer[MAX_SIZE];

    RAND_load_file("/dev/random", 16);
    unsigned char key[16];
    RAND_bytes(key, 16);
    
    unsigned char iv[16];
    RAND_bytes(iv, 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *mode = EVP_get_cipherbyname(argv[2]);
    EVP_CipherInit(ctx, mode, key, iv, ENCRYPT);

    unsigned char ciphertext[1000*MAX_SIZE];
    int len, ciphertext_len = 0;

    while( (n_read = fread(buffer, 1, MAX_SIZE, f_in)) > 0){
        if(ciphertext_len > 1000*MAX_SIZE - n_read - EVP_CIPHER_block_size(mode)){
            fprintf(stderr, "File too large");
        }
        EVP_CipherUpdate(ctx, ciphertext+len, &len, buffer, n_read);
        ciphertext_len+=len;
    }

    EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &len);
    ciphertext_len+=len;

    ciphertext[ciphertext_len] = '\0';

    printf("Ecco il testo cifrato: \n %s", ciphertext);


    fclose(f_in);
    

    // EVP_CipherUpdate(ctx, ciphertext, &len, )

    
    return 0;
}