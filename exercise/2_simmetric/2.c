// Key & IV = 123456789012345678901234567890AB

// Exercise 2.2. Write a program that decrypts the content of a file, passed as the first parameter from
//  the command line, using the key and IV passed as the second and third parameters. The program
//  must save the decrypted file into a file whose name is the fourth parameter (i.e., decrypt the result of
//  the encryption of enc4.c on GitHub).

#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MAXBUFFER 1024

int main(int argc, char *argv[]){
    if(argc != 5){
        fprintf(stderr, "Error using tool\n");
        abort();
    }

    // Encrypted file
    FILE *f_encrypted = fopen(argv[1], "rb");

    // Take the key
    unsigned char key[strlen(argv[2])/2];
    for(int i = 0; i < strlen(argv[2])/2; ++i)
        sscanf(&argv[2][2*i], "%2hhx", &key[i]);

    // Take the iv
    unsigned char iv[strlen(argv[3])/2];
    for(int i = 0; i < strlen(argv[3])/2; ++i)
        sscanf(&argv[3][2*i], "%2hhx", &iv[i]);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, DECRYPT);
    
    int n_read;
    unsigned char buffer[MAXBUFFER];

    // plaintext
    unsigned char plaintext[100*MAXBUFFER];
    int len;

    // Output file
    FILE *f_decrypt = fopen(argv[4], "wb");

    while((n_read = fread(buffer, 1, MAXBUFFER, f_encrypted)) > 0){
        EVP_CipherUpdate(ctx, plaintext, &len, buffer, n_read);

        fwrite(plaintext, 1, len, f_decrypt);
    }

    EVP_CipherFinal(ctx, plaintext, &len);
    fwrite(plaintext, 1, len, f_decrypt);

    EVP_CIPHER_CTX_free(ctx); // Libera il contesto di crittografia
    
    fclose(f_encrypted);
    fclose(f_decrypt);
    
    return 0;
}