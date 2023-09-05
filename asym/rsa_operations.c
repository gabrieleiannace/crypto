#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

int main(int argc, char *argv[]){
    
    
    unsigned char msg[] = "This is the message to encrypt with RSA";

    RSA *key_pair = RSA_new();
    int bits = 2048;
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);

    RSA_generate_key_ex(key_pair, bits, bne, NULL);

    unsigned char encrypted_data[RSA_size(key_pair)]; //Mi aspetto che i dati crittati siano della stessa dimensione della chiave
    int encrypted_data_len;

    encrypted_data_len = RSA_public_encrypt(strlen(msg)+1, msg, encrypted_data, key_pair, RSA_PKCS1_OAEP_PADDING);

    //Scrivo i dati crittati sul file
    FILE *f_out;
    f_out = fopen("out.bin", "w");

    fwrite(encrypted_data, 1, encrypted_data_len, f_out);

    fclose(f_out);

    // Proviamo ora a decrittare questo file.
    FILE *f_in = fopen("out.bin", "r");
    fread(encrypted_data, 1, sizeof(RSA_size(key_pair)), f_out);
    printf("%s\n", encrypted_data);

    unsigned char decrypted_data[RSA_size(key_pair)];
    int decrypted_data_len;
    decrypted_data_len = RSA_private_decrypt(encrypted_data_len, encrypted_data, decrypted_data, key_pair, RSA_PKCS1_OAEP_PADDING);

    printf("%s", decrypted_data);




    RSA_free(key_pair);
    BN_free(bne);

    
    return 0;
}