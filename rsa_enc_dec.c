#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>


int main(int argc, char *argv[]) {

    /*
        Initialize the TPM context
    */
    ESYS_CONTEXT *esysContext;
    TSS2_RC rc = Esys_Initialize(&esysContext, NULL, NULL);
    if (rc != TPM2_RC_SUCCESS) {
        printf("Initialize Context Failed\n");
        return 1;
    }
    printf("Initialize Context Success.\n");


    /*
        Generate primary rsa key
    */
    
    // inSensitivePrimary is the sensitive data portion of the primary key: authorization value and user data
    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
        .sensitive = {
            .userAuth = {   // This is the athorization value which is used to control access to the key and to authorize operations involving that key
                 .size = 5,
                 .buffer = {1,2,3,4,5},
             },
            .data = {   // This is private user data (e.g., user-defined secret data, cryptographic seeds, or personal identification numbers (PINs))
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    // inPublic is the public portion of the key 
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,   // type of key --> RSA 
            .nameAlg = TPM2_ALG_SHA256, // algorithm used for name generation --> SHA256
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | // key requires user authorization for its use (authorization value)
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |  // key cannot be duplicated to a different parent key
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN), // sensitive part is generated within the TPM
            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL},
                 .scheme = { .scheme = TPM2_ALG_RSAES },    //  RSAES (RSA Encryption Scheme) 
                 .keyBits = 2048,
                 .exponent = 0,
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {},
             },
        },
    };




    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {  // specifies which PCR values should be used
        .count = 0, // no PCR values are being selected, so the creation of the key is not conditioned on the state of any PCR
    };
    /*
        Q: What are PCRs (Platform Configuration Registers)?
        A: Represent the state of the system's software environment, such as the BIOS, bootloader, operating system

    */

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}
    };

    ESYS_TR primaryHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;


    // Set the authorization value (password) for the ESYS_TR_RH_OWNER 
    rc = Esys_TR_SetAuth(esysContext, ESYS_TR_RH_OWNER, &authValue);
    if (rc != TPM2_RC_SUCCESS) {
        printf("First Esys_TR_SetAuth Failed\n");
        return 1;
    }
    printf("First Esys_TR_SetAuth Success.\n");

    

    // Create primary rsa key
    rc = Esys_CreatePrimary(esysContext, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                               ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                               &inPublic, &outsideInfo, &creationPCR,
                               &primaryHandle, &outPublic, &creationData,
                               &creationHash, &creationTicket);
    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_CreatePrimary Failed\n");
        return 1;
    }
    printf("Esys_CreatePrimary Success.\n");



    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };
    // Set the authorization value for the primary key (matches what was declared in inSensitivePrimary)
    rc = Esys_TR_SetAuth(esysContext, primaryHandle, &authValuePrimary);
    if (rc != TPM2_RC_SUCCESS) {
        printf("Second Esys_TR_SetAuth Failed\n");
        return 1;
    }
    printf("Second Esys_TR_SetAuth Success.\n");




    printf("Primary RSA Key Created Successfully...\n");





    /*
        Encrypting using RSA key
    */
    size_t plain_size = 3;
    TPM2B_PUBLIC_KEY_RSA plain = {.size = plain_size,.buffer = {1, 2, 3}}; // plain text

    TPMT_RSA_DECRYPT inScheme;
    inScheme.scheme = TPM2_ALG_RSAES;

    TPM2B_PUBLIC_KEY_RSA *cipher = NULL;
    
    rc = Esys_RSA_Encrypt(esysContext, primaryHandle, ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &plain, &inScheme,
                             NULL, &cipher);
    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_RSA_Encrypt Failed\n");
        return 1;
    }
    printf("Encryption Success.\n");

    // Printing
    printf("Plain Data: ");
    for (size_t i = 0; i < plain.size; i++) {
        printf("%d ", plain.buffer[i]);
    }
    printf("\n");
    printf("Cipher Data: ");
    for (size_t i = 0; i < cipher->size; i++) {
        printf("%d ", cipher->buffer[i]);
    }
    printf("\n");
               





    /*
        RSA Decryption
    */
    TPM2B_PUBLIC_KEY_RSA *decrypted = NULL;
    rc = Esys_RSA_Decrypt(esysContext, primaryHandle,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             cipher, &inScheme, NULL, &decrypted);
    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_RSA_Decrypt Failed\n");
        return 1;
    }
    printf("Decryption Success.\n");


    /*
        Q: Why is there ESYS_TR_PASSWORD in Esys_RSA_Decrypt but not in Esys_RSA_Encrypt?
        A: 
            - When encrypting data (Esys_RSA_Encrypt), the TPM typically does not require authorization for the key being 
                used because its uses the public key which is not sensitive or private
            - In contrast, decryption (Esys_RSA_Decrypt) typically requires authorization because it involves accessing
                the private key.
    */

    // Printing
    printf("Decrypted Data: ");
    for (size_t i = 0; i < decrypted->size; i++) {
        printf("%d ", decrypted->buffer[i]);
    }
    printf("\n");






    /*
        Checking for equality:
    */
    int isEqual = 1; // Assuming 1 for true (equal), 0 for false (not equal)

    if (plain.size != decrypted->size) {
        isEqual = 0;
    } else {
        for (size_t i = 0; i < plain.size; i++) {
            if (plain.buffer[i] != decrypted->buffer[i]) {
                isEqual = 0;
                break;
            }
        }
    }

    // Print the result
    if (isEqual) {
        printf("-----Decrypted data matches plain data.-----\n");
    } else {
        printf("Decrypted data does not match plain data.\n");
    }





    /*
        Free resources
    */
    Esys_Free(cipher);
    Esys_Free(decrypted);
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_FlushContext(esysContext, primaryHandle);
    Esys_Finalize(&esysContext);



    return 0;

}