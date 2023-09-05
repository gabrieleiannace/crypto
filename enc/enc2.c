#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MAXSIZE 1024

void handle_errors(){

    ERR_print_errors_fp(stderr);
    abort();
}

// VARIAZIONE: VOGLIAMO SALVARE SU DI UN FILE IL RISULTATO
// Assumiamo che:
    // argv[1] = input file
    // argv[2] = key
    // argv[3] = IV
    // argv[4] = output file

int main(int argc, char *argv[]){

    //Per il funzionamento della gestione degli errori
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if(argc != 5){
        fprintf(stderr, "Error: Invalid parameters. Usage %s input_file key IV output_file\n", argv[0]);    
        exit(1);
    }

    FILE *f_in;
    if( (f_in = fopen(argv[1], "r")) == NULL ){
        fprintf(stderr, "Erorrs opening the input file: %s\n", argv[1]);
        exit(1);
    }

    FILE *f_out;
    if( (f_out = fopen(argv[4], "wb")) == NULL ){
        fprintf(stderr, "Erorrs opening the input file: %s\n", argv[1]);
        exit(1);
    }

    if(strlen(argv[2])/2  != 32 ){
        fprintf(stderr, "WRONG KEY LENGHT: %s\n", argv[1]);
    }

    unsigned char key[strlen(argv[2])/2];

    for(int i = 0; i < strlen(argv[2])/2; ++i)
        sscanf(&argv[2][2*i], "%2hhx", &key[i]);
    


    if(strlen(argv[3])/2  != 32 ){
        fprintf(stderr, "WRONG IV LENGHT: %s\n", argv[1]);
    }

    unsigned char IV[strlen(argv[3])/2];

    for(int i = 0; i < strlen(argv[3])/2; ++i)
        sscanf(&argv[3][2*i], "%2hhx", &IV[i]);


    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //NULL CHECK;

    if(! EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, IV, ENCRYPT))
        handle_errors();


    int n_read; 
    unsigned char buffer[MAXSIZE];


    //VARIAZIONE
    unsigned char ciphertext[MAXSIZE + 16];

    int len, ciphertext_len = 0;

    while( (n_read = fread(buffer, 1, MAXSIZE, f_in)) > 0 ){
        //ci sono i dati nel file


        //VARIAZIONE
        if(!EVP_CipherUpdate(ctx, ciphertext, &len, buffer, n_read))
            handle_errors();

        ciphertext_len+= len;

        //VARIAZIONE
        if(fwrite(ciphertext, 1, len, f_out) < len){
            fprintf(stderr, "Error writing into the output file \n");
            abort();
        }

    }

    //VARIAZIONE
    if(!EVP_CipherFinal(ctx, ciphertext, &len))
        handle_errors();

    ciphertext_len+=len;

    //VARIAZIONE
    if(fwrite(ciphertext, 1, len, f_out) < len){
        fprintf(stderr, "Error writing into the output file \n");
        abort();
    }

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext lenght = %d\n", ciphertext_len);
    //cancellazione


    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();


    //VARIAZIONE
    fclose(f_in);
    fclose(f_out);
    return 0;
}