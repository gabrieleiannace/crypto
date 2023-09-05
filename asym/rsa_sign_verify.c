#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define MAXSIZE 1024

int main(int argc, char *argv[]){
    
    if(argc != 4){
        abort();
    }

    FILE *f_priK = fopen(argv[2], "r");
    EVP_PKEY *priK = PEM_read_PrivateKey(f_priK, NULL, NULL, NULL);
    fclose(f_priK);

    // sign_file private_key public_key
    FILE *f_sign = fopen(argv[1], "r");
    unsigned char buffer[MAXSIZE];
    int n_read;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, priK);

    while((n_read = fread(buffer, 1, MAXSIZE, f_sign)) > 0){
        EVP_DigestSignUpdate(md_ctx, buffer, n_read);
    }

    size_t sign_len;
    EVP_DigestSignFinal(md_ctx, NULL, &sign_len);
    unsigned char signature[sign_len];
    EVP_DigestSignFinal(md_ctx, signature, &sign_len);
    fclose(f_sign);

    FILE *f_out = fopen("out.bin", "w");
    fwrite(signature, 1, sign_len, f_out);
    fclose(f_out);

    FILE *f_pubK = fopen(argv[3], "r");
    EVP_PKEY *pubK = PEM_read_PUBKEY(f_pubK, NULL, NULL, NULL);
    fclose(f_pubK);

    FILE *f_in = fopen("out.bin", "r");

    unsigned char signature_from_file [MAXSIZE]; // we don't know in advance the size of the signature
    
    size_t sig_len_from_file;
    if ((sig_len_from_file = fread(signature_from_file, 1, MAXSIZE, f_in)) != EVP_PKEY_size(pubK))
        abort();
    printf("%s", signature_from_file);
    printf("%d", sig_len_from_file);
    


    EVP_MD_CTX *verify_ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(verify_ctx, NULL, EVP_sha256(), NULL, pubK);


    fclose(f_in);

}