//  Exercise 1.4. Using OpenSSL, generate two 32-bit integers (int), multiply them (modulo 2^32) and
//  print the result.

#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>


void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char *argv[]){
    unsigned char a[4];
    unsigned char b[4];

    if(RAND_load_file("/dev/random", 4) != 4)

    if(!RAND_bytes(a, 4))
        handle_errors();

    if(RAND_load_file("/dev/random", 4) != 4)

    if(!RAND_bytes(b, 4))
        handle_errors();

    printf("%d\n", a);
    printf("%d\n", b);

    // ??????????????????????????????????????????????????????????????????????
    
    
    return 0;
}