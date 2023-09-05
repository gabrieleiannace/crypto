//  Exercise 1.1. Write a program in C that, using the OpenSSL library, generates two 128-bit random
//  strings. Then, it XOR them (bitwise/bytewise) and prints the result on the standard output as a hex
//  string

#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define MAX 128

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}


int main(int argc, char *argv[]){
    unsigned char random_string1[MAX];
    unsigned char random_string2[MAX];

    if(RAND_load_file("/dev/random", 64) != 64)
        handle_errors();

    if(!RAND_bytes(random_string1,MAX))
        handle_errors();

    if(!RAND_bytes(random_string2,MAX))
        handle_errors();

    unsigned char result[MAX];
    for(int i = 0; i < MAX; ++i)
        result[i] = random_string1[i] ^ random_string2[i];

    for(int i = 0; i < MAX; ++i)
        printf("%02x", result[i]);
    return 0;
}