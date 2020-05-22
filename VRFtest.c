//
//  VRFtest.c
//  VRFtest
//
//  Created by Cesar Grajales on 07/05/20.
//  Copyright © 2020 Grajales. All rights reserved.
//
// Generation of verifiable hashes with a VRF
// The user is asked for the number of hashes and a seed
// The seed can be any text string
// The SHA-256 hash of the seed is used as input to the VRF
// The program generates the secret an public keys
// as well as the verifiable hashes and the corresponding proofs.
// The secret keys are written to the secretKeys.txt file
// The public keys are written to the publicKeys.txt file
// The hashes are written to the randomNumbers.txt file
// The proofs are written to the proofs.txt file

#include <stdio.h>
#include <sodium.h>
#include <string.h>

#define MAX 100

int main(){
    
    char signedSeed[MAX] = "";
    unsigned char seed[MAX] = "";
    unsigned char hashedSeed[32] = "";
    unsigned char proof[80] = "";
    unsigned char randomNumber[64] = "";
    unsigned char verifyOut[64] = "";
    int z=0;
    int i=0;
    int j=0;
    unsigned char pk[32] = "";
    unsigned char sk[64] = "";
    int numberOfKeys = 0;
    
    FILE *secretKeysFile;
    FILE *publicKeysFile;
    FILE *randomNumbersFile;
    FILE *proofsFile;
    
    secretKeysFile = fopen("secretKeys.txt", "w");
    publicKeysFile = fopen("publicKeys.txt", "w");
    randomNumbersFile = fopen("randomNumbers.txt", "w");
    proofsFile = fopen("proofs.txt","w");
    
    if (publicKeysFile && secretKeysFile && randomNumbersFile && proofsFile) {
        
        printf("How many key pairs do you need? ");
        scanf("%d", &numberOfKeys);
        
        printf("Tell me the seed for the random numbers: ");
        scanf("%s", signedSeed);
        
        for(i=0;i<=strlen(signedSeed)-1;i=i+1){
        
            seed[i]=(unsigned char)signedSeed[i];
        }
        
        crypto_hash_sha256(hashedSeed, seed, strlen(signedSeed));

        printf("seed:   ");
        
        for(i=0;i<=31;i++) {
            printf("%02X", hashedSeed[i]);
        }
        
        printf("\n \n");
        
        for(j=1; j<=numberOfKeys; j=j+1) {

            // crypto_vrf_keypair(pk, sk);
            crypto_vrf_ietfdraft03_keypair(pk, sk);
            // crypto_vrf_prove(proof, sk, hashedSeed, 32);
            // crypto_vrf_proof_to_hash(randomNumber, proof);
            crypto_vrf_ietfdraft03_prove(proof, sk, hashedSeed, 32);
            crypto_vrf_ietfdraft03_proof_to_hash(randomNumber, proof);
            // z=crypto_vrf_verify(verifyOut, pk, proof, hashedSeed, crypto_hash_sha256_BYTES);
            z = crypto_vrf_ietfdraft03_verify(verifyOut, pk, proof, hashedSeed, 32);
            
            if(crypto_vrf_is_valid_key(pk)==1){
                printf("Is pk valid?: YES\n");
            } else {
                printf("Is pk valid?: NO\n");
            }
            
            printf("pk:     ");
            
            for(i=0;i<=31;i=i+1){
                printf("%02X",pk[i]);
                fprintf(publicKeysFile, "%02X", pk[i]);
            }
            printf("\n");
            fprintf(publicKeysFile,"\n");
            
            printf("sk:     ");
            for(i=0;i<=63;i=i+1){
                printf("%02X",sk[i]);
                fprintf(secretKeysFile, "%02X", sk[i]);
            }
            printf("\n");
            fprintf(secretKeysFile,"\n");
            
            printf("v hash: ");
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
            
            if(z==0){
                printf("pass?:  OK -> v hash: ");
                for(i=0;i<=63;i=i+1){
                    printf("%02X",verifyOut[i]);
                }
                printf("\n \n");
            } else {
                printf("pass?:  NO");
            }
            
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

