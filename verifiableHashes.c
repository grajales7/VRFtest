//
//  verifiableHashes.c
//  VRFtest
//
//  Created by Cesar Grajales on 10/05/20.
//  Copyright © 2020 Grajales. All rights reserved.
//

#include <stdio.h>
#include <sodium.h>
#include <string.h>

#define MAX 256

int main(){
    
    char signedSeed[MAX] = "";
    unsigned char seed[MAX] = "";
    char signedSK[MAX] = "";
    char asciiSK[MAX] = "";
    char signedPK[MAX] = "";
    char asciiPK[MAX] = "";
    unsigned char hashedSeed[32] = "";
    unsigned char proof[80] = "";
    unsigned char randomNumber[64] = "";
    unsigned char SK[64] = "";
    unsigned char PK[32] = "";
    unsigned char verifyOut[64] = "";
    char tmpChar[2] = "";
    int tmpInt=0;
    int z=0;
    
    int i=0;
    int j=0;
    
    FILE *secretKeysFile;
    FILE *publicKeysFile;
    FILE *randomNumbersFile;
    FILE *proofsFile;
    
    secretKeysFile = fopen("secretKeys.txt", "r");
    publicKeysFile = fopen("publicKeys.txt", "r");
    randomNumbersFile = fopen("randomNumbers_.txt", "w");
    proofsFile = fopen("proofs_.txt","w");
    
    printf("The secret (private) keys will be read from 'secretKeys.txt' file.\n");
    printf("Please enter the seed for the random numbers (a text string): ");
    scanf("%s", signedSeed);
    printf("\n");
    
    for(i=0;i<=strlen(signedSeed)-1;i=i+1){
        seed[i]=(unsigned char)signedSeed[i];
    }
    
    crypto_hash_sha256(hashedSeed, seed, strlen(signedSeed));

    printf("hashed seed: ");
    
    for(i=0;i<=31;i++) {
        printf("%02X", hashedSeed[i]);
    }
    printf("\n\n");
    
    if (publicKeysFile && secretKeysFile && randomNumbersFile && proofsFile) {
        
            while (fgets(asciiPK, MAX, publicKeysFile) != '\0') {
                
                if(asciiPK[strlen(asciiPK)-1]=='\n') {
                    asciiPK[strlen(asciiPK)-1] = 0;
                }
                
                j=0;
                for(i=0;i<strlen(asciiPK);i=i+2){
                    tmpChar[0]=asciiPK[i];
                    tmpChar[1]=asciiPK[i+1];
                    tmpInt = 0;
                    sscanf(tmpChar, "%02X",&tmpInt);
                    signedPK[j]=tmpInt;
                    PK[j] = (unsigned char)signedPK[j];
                    j=j+1;
                }
                
                fgets(asciiSK, MAX, secretKeysFile);
                
                if(asciiSK[strlen(asciiSK)-1]=='\n') {
                    asciiSK[strlen(asciiSK)-1] = 0;
                }
                
                j=0;
                for(i=0;i<strlen(asciiSK);i=i+2){
                    tmpChar[0]=asciiSK[i];
                    tmpChar[1]=asciiSK[i+1];
                    sscanf(tmpChar, "%02X", &tmpInt);
                    signedSK[j]=tmpInt;
                    SK[j] = (unsigned char)signedSK[j];
                    j=j+1;
                }
                
                crypto_vrf_prove(proof, SK, hashedSeed, 32);
                crypto_vrf_proof_to_hash(randomNumber, proof);
                
                //crypto_vrf_ietfdraft03_prove(proof, SK, hashedSeed, 32);
                //crypto_vrf_ietfdraft03_proof_to_hash(randomNumber, proof);
                
                printf("PK:     ");
                for(i=0;i<=31;i=i+1){
                    printf("%02X",PK[i]);
                }
                printf("\n");
                
                printf("SK:     ");
                for(i=0;i<=63;i=i+1){
                    printf("%02X",SK[i]);
                }
                printf("\n");
                
                printf("num:    ");
                for(i=0;i<=63;i=i+1){
                    printf("%02X",randomNumber[i]);
                    fprintf(randomNumbersFile, "%02X", randomNumber[i]);
                }
                printf("\n");
                fprintf(randomNumbersFile,"\n");
                
                printf("proof:  ");
                for(i=0;i<=79;i=i+1){
                    printf("%02X",proof[i]);
                    fprintf(proofsFile, "%02X", proof[i]);
                }
                printf("\n");
                fprintf(proofsFile,"\n");
                
                z=crypto_vrf_verify(verifyOut, PK, proof, hashedSeed, 32);
                
                if(z==0){
                    printf("Pass?   OK ");
                    printf("num: -> ");
                    for(i=0;i<=63;i=i+1){
                        printf("%02X",verifyOut[i]);
                    }
                } else{
                    printf("Pass? NO ");
                }
                printf("\n\n");
            }
        
        fclose(secretKeysFile);
        fclose(publicKeysFile);
        fclose(randomNumbersFile);
        fclose(proofsFile);
        
    }
    
    else{
        printf("Error \n");
        return(-1);
    }
    
    return(0);
}
