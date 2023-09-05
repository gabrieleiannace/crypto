#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

int main(int argc, char *argv[]){
    
    RSA *rsa_keypair = NULL;

    BIGNUM *bne = BN_new();
    unsigned long e = RSA_F4;
    int bit = 2048;
    
    BN_set_word(bne, e);
    
    rsa_keypair = RSA_new();
    RSA_generate_key_ex(rsa_keypair, bit, bne, NULL);

    //  2. Save the public key
    FILE *rsa_public_file = NULL;
    rsa_public_file = fopen("public.pem", "w");

    PEM_write_RSA_PUBKEY(rsa_public_file, rsa_keypair);

    fclose(rsa_public_file);

    // 3. Save the private key
    FILE *rsa_private_file = NULL;
    rsa_private_file = fopen("private.pem", "w");

    PEM_write_RSAPrivateKey(rsa_private_file, rsa_keypair, NULL, NULL, 0, NULL, NULL);

    fclose(rsa_private_file);

    RSA_free(rsa_keypair);
    BN_free(bne);

    
    return 0;
}