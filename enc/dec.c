#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>

#define ENCRYPT 1
#define DECRYPT 0

int main(){
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
    unsigned char ciphertext[] = "da1376fd7603781be862e2bf2a9b85e1ccb0684301f7771fcc9994f8f589921b373fd20dff51f13ee58c26880e8350cc"; 

    //Init ctx
    // Nota: stiamo utilizzando AES a 128bits in modalitá CBC
    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, DECRYPT);

    unsigned char plaintext[strlen(ciphertext)/2];
    unsigned char ciphertext_bin[strlen(ciphertext)/2];

    for(int i = 0; i < strlen(ciphertext)/2; ++i)
        sscanf(&ciphertext[2*i], "%2hhx", &ciphertext_bin[i]);
    
    int lenght;
    int plaintext_len = 0;
    //Lenght contiene la dimensione dei dati giá processati
    EVP_CipherUpdate(ctx, plaintext, &lenght, ciphertext_bin, strlen(ciphertext)/2);

    printf("After update: %d\n", lenght);
    plaintext_len+=lenght;

    EVP_CipherFinal(ctx, plaintext+plaintext_len, &lenght);
    printf("After final: %d\n", lenght);
    plaintext_len+=lenght;

    EVP_CIPHER_CTX_free(ctx);


    //Questo lo posso fare solo perchè so con certezza di non usare tutti  i 48 bits ma solo 44, altrimenti devo allocare qualche byte in più 
    plaintext[plaintext_len] = '\0';
    printf("Plaintext = %s\n", plaintext);


    return 0;
}