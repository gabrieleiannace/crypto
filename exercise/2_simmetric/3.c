// Exercise 2.3. Implement a program that encrypts a file whose name is passed as the first parameter
// from the command line using a stream cipher. Using the C XOR function, apply a 128-bit mask to the
// encrypted content (of your choice, or just select ‘11..1’), decrypt, and check the result.

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MAXBUFFER 1024

int main(int argc, char *argv[]){
    OpenSSL_add_all_algorithms();

    unsigned char mask[] = {0xFF, 0xFF, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    unsigned char key[] = "1234567890abcdef";
    unsigned char iv[] = "1234567890abcdef";

    if(argc != 2){
        fprintf(stderr, "Error using the tool\n");
        abort();
    }

    // Encrypt

    FILE *f_encrypt = fopen(argv[1], "rb");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT);

    int n_read;
    unsigned char buffer[MAXBUFFER];
    unsigned char ciphertext[100*MAXBUFFER];
    int ciphertext_len = 0, len;

    while( (n_read = fread(buffer, 1, MAXBUFFER, f_encrypt)) > 0){
        if(ciphertext_len > 100*MAXBUFFER - n_read - EVP_CIPHER_CTX_block_size(ctx))
            abort();
        EVP_CipherUpdate(ctx, ciphertext+ciphertext_len, &len, buffer, n_read);
        ciphertext_len+=len;
    }

    EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &len);
    ciphertext_len+=len;

    EVP_CIPHER_CTX_free(ctx);

    int pos = 0;
    for(int i = 0; i < ciphertext_len/16; ++i){
        for(int j = 0; j < 16; ++j){
            ciphertext[pos] ^= mask[j]; 
        }
        pos += 16;
    }

    // Decrypt

    unsigned char plaintext[100*MAXBUFFER];
    int plaintext_len = 0;
    EVP_CIPHER_CTX *decrypt_ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(decrypt_ctx, EVP_aes_128_cbc(), key, iv, DECRYPT);
    EVP_CipherUpdate(decrypt_ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len += len;
    EVP_CipherFinal(decrypt_ctx, plaintext, &len);
    plaintext_len+=len;

    plaintext[plaintext_len] = '\0';
    // printf("%s\n", ciphertext);
    printf("%s\n", plaintext);

    fclose(f_encrypt);
    
    
    
    return 0;
}