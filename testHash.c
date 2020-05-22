//
//  testHash.c
//  VRFtest
//
//  Created by Cesar Grajales on 04/05/20.
//  Copyright © 2020 Grajales. All rights reserved.
//

// SHA256 test hash

#include <stdio.h>
#include <sodium.h>
#include <string.h>

#define MAX 100

int main(){
    
    char in_string[MAX] = "";
    unsigned char input_string[MAX] = "";
    unsigned char hashed_string[crypto_hash_sha256_BYTES] = "";
    int i;
    
    printf("Tell me the input string: ");
    scanf("%s", in_string);
    
    for(i=0;i<=strlen(in_string)-1;i++){
        input_string[i]=(unsigned char)in_string[i];
    }
    
    crypto_hash_sha256(hashed_string, input_string, strlen(in_string));
    
    printf("input string: %s\n", (char*)input_string);
    printf("hashed string: ");
    
    for(i=0;i<=31;i++) {
        printf("%02X", hashed_string[i]);
    }
    
    printf("\n");
    return 0;
}
