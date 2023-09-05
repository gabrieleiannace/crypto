#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0


void handle_errors(){

    ERR_print_errors_fp(stderr);
    abort();
}

int main(){

    //Per il funzionamento della gestione degli errori
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();


    // Note: ricordare che il chipertext è grande più o meno quando il plaintext
    // ma bisogna considerare del padding

    // Note: bisogna utilizzare una modalitá di crittografia: ECB, CBC, OFB, CFB...
    // può essere necessario utilizzare un IV
    // ci sono block algorithms o stream algorithms

    // OpenSSL utilizza un approccio basato su "incremental updates"
    // ciò significa che bisogna prima di tutto inizializzare il contesto
    // poi bisogna in un ciclo andare a enc o dec un frammento (blocco)
    // giunti alla fine del cilco dobbiamo fare una "finalization" che compone il tutto
    // e rimuove o aggiunge il padding al blocco finale

    // I passi da seguire: Creazione ctx, init ctx, [CYCLE] Update, Final

    //Creazione ctx
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    unsigned char key[] = "1234567890abcdef";
    unsigned char iv[] = "abcdef1234567890";


    //Init ctx
    // Nota: stiamo utilizzando AES a 128bits in modalitá CBC
    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();

    unsigned char plaintext[] = "This is the plaintext to encrypt."; //len 33
    unsigned char ciphertext[48];//48 è il multiplo più vicino

    
    int update_len, final_len;
    int ciphertext_len=0;


    //update_len contiene la dSSimensione dei dati giá processati
    if(!EVP_CipherUpdate(ctx, ciphertext, &update_len, plaintext, strlen(plaintext)))
        handle_errors();

    printf("After update %d\n", update_len);
    ciphertext_len += update_len;

    if(!EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &final_len))
        handle_errors();
    printf("After final %d\n", final_len);
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Size of the ciphertext = %d\n", ciphertext_len);
    
    //ciclo su ogni byte e scrivo la rapresentazione esadecimale
    for(int i = 0; i < ciphertext_len; ++i)
        printf("%02x", ciphertext[i]);

    printf("\n");

    //Pulisci tutto in memoria
    CRYPTO_cleanup_all_ex_data();
    //Pulizia della stringa di errori
    ERR_free_strings();

    return 0;
}