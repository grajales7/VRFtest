//
//  VRFkeys.c
//  VRFtest
//
//  Created by Cesar Grajales on 07/05/20.
//  Copyright © 2020 Grajales. All rights reserved.
//
// Generation of key pairs for use in a VRF
// User specifies a number of key pairs
// The resulting keys are written to two text files
// publicKeys.txt for the public keys
// secretKeys.txt for the private (secret) keys

#include <stdio.h>
#include <sodium.h>
#include <string.h>

#define MAX 100

int main(){
    
    unsigned char pk[MAX] = "";
    unsigned char sk[MAX] = "";
    int numberOfKeys = 0;
    int i=0;
    int j=0;
    
    FILE *fileOut1;
    FILE *fileOut2;
    
    fileOut1 = fopen("publicKeys.txt", "w");
    fileOut2 = fopen("secretkeys.txt", "w");
    
    if (fileOut1 && fileOut2) {
        
        printf("How many key pairs do you need? \n");
        scanf("%d", &numberOfKeys);
        
        for(j=1; j<=numberOfKeys; j=j+1) {
            
            crypto_vrf_keypair(pk, sk);
            
            printf("pk: ");
            i=0;
            while(pk[i]!='\0'){
                printf("%02X",pk[i]);
                fprintf(fileOut1, "%02X", pk[i]);
                i=i+1;
            }
            printf("\n");
        
            fprintf(fileOut1,"\n");
            
            i=0;
            printf("sk: ");
            while(sk[i]!='\0'){
                printf("%02X",sk[i]);
                fprintf(fileOut2, "%02X", sk[i]);
                i=i+1;
            }
            printf("\n");

            fprintf(fileOut2,"\n");
            
            memset(pk,0,sizeof(pk));
            memset(sk,0,sizeof(sk));
            
        }
        
        fclose(fileOut1);
        fclose(fileOut2);
            
    }
    
    else{
        printf("Error \n");
        return(-1);
    }
    
    return(0);
}
