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

int main(int argc, char *argv[]){
    OpenSSL_add_all_algorithms();

    
    
    
    
    return 0;
}