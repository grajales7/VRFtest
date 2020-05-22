//
//  VRFshortTest.c
//  VRFtest
//
//  Created by Cesar Grajales on 20/05/20.
//  Copyright © 2020 Grajales. All rights reserved.
//

#include <stdio.h>
#include <sodium.h>

#define MAX 100

int main(void) {
    
    unsigned char pk[32] = {0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c};
    

    unsigned char sk[64] = {0x4c,0xcd,0x08,0x9b,0x28,0xff,0x96,0xda,0x9d,0xb6,0xc3,0x46,0xec,0x11,0x4e,0x0f,0x5b,0x8a,0x31,0x9f,0x35,0xab,0xa6,0x24,0xda,0x8c,0xf6,0xed,0x4f,0xb8,0xa6,0xfb,0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c};
    
    unsigned char pk_[32] = "";
    unsigned char skpk[64] = "";
    
    unsigned char alpha[1] = {0x72};
    
    unsigned char pi[80] = "";
    unsigned char beta[64] = "";
    
    unsigned char verifyOut[64] = "";
    
    int z=3;
    int i=0;
        
    crypto_vrf_ietfdraft03_prove(pi, sk, alpha, 1);

    crypto_vrf_ietfdraft03_proof_to_hash(beta, pi);
    
    z = crypto_vrf_ietfdraft03_verify(verifyOut, pk, pi, alpha, 1);
    
    crypto_vrf_sk_to_pk(pk_, skpk);
    
    printf("is pk valid? %d \n\n",crypto_vrf_is_valid_key(pk));
    
    printf("in:     ");
    for(i=0;i<=0;i=i+1){
        printf("%02X",alpha[i]);
    }
    printf("\n");
    
    printf("pk:     ");
    for(i=0;i<=31;i=i+1){
        printf("%02X",pk[i]);
    }
    printf("\n");
    
    printf("sk:     ");
    for(i=0;i<=63;i=i+1){
        printf("%02X",sk[i]);
    }
    printf("\n");
    
    printf("v hash: ");
    for(i=0;i<=63;i=i+1){
        printf("%02X",beta[i]);
    }
    printf("\n");
    
    printf("pi:     ");
    for(i=0;i<=79;i=i+1){
        printf("%02X",pi[i]);
    }
    printf("\n");
    
    // z=crypto_vrf_verify(verifyOut, pk, pi, hashedSeed, crypto_hash_sha256_BYTES);
    
    printf("pass?:  %d - ",z);
    for(i=0;i<=63;i=i+1){
        printf("%02X",verifyOut[i]);
    }
    printf("\n \n");
    
}
