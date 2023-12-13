#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>


// Functions
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

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
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB},
                .scheme = {
                    .scheme = TPM2_ALG_NULL
                },
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
        AES Key
    */

   // Generate a random AES key using OpenSSL
    unsigned char aes_key[16]; // 128-bit AES key
    if (!RAND_bytes(aes_key, sizeof(aes_key))) {
        printf("Failed to generate AES key\n");
        return 1;
    }
    printf("AES Key generated.\n");

    // Print the key (obvioudly unsafe)
    printf("AES Key: ");
    for (int i = 0; i < sizeof(aes_key); i++) {
        printf("%02x", aes_key[i]); // Print each byte in hex format
    }
    printf("\n");




    // Prepare the sensitive data structure with the AES key
    TPM2B_SENSITIVE_DATA sensitiveData = {
        .size = sizeof(aes_key),
        .buffer = {0}
    };
    memcpy(sensitiveData.buffer, aes_key, sizeof(aes_key));




    TPM2B_AUTH authKey2 = {
        .size = 6,
        .buffer = {6, 7, 8, 9, 10, 11}
    };
    TPM2B_SENSITIVE_CREATE inSensitive2 = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                .size = 0,
                .buffer = {0}
            },
            .data = sensitiveData
        }
    };

    inSensitive2.sensitive.userAuth = authKey2;



    TPM2B_PUBLIC inPublic2 = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_KEYEDHASH,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (
                TPMA_OBJECT_USERWITHAUTH |
                /* TPMA_OBJECT_RESTRICTED | */
                /* TPMA_OBJECT_DECRYPT | */
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT
                /* TPMA_OBJECT_SENSITIVEDATAORIGIN */
            ),

            .authPolicy = {
                .size = 0,
            },
            .parameters.keyedHashDetail = {
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {
                        .hmac = {
                            .hashAlg = TPM2_ALG_SHA256
                        }
                    }
                }
            },
            .unique.keyedHash = {
                .size = 0,
                .buffer = {},
            },
        }
    };

    TPM2B_DATA outsideInfo2 = {
        .size = 0,
        .buffer = {}
        ,
    };

    TPML_PCR_SELECTION creationPCR2 = {
        .count = 0,
    };


    TPM2B_PUBLIC *outPublic2 = NULL;
    TPM2B_PRIVATE *outPrivate2 = NULL;
    TPM2B_CREATION_DATA *creationData2 = NULL;
    TPM2B_DIGEST *creationHash2 = NULL;
    TPMT_TK_CREATION *creationTicket2 = NULL;

    rc = Esys_Create(esysContext,
                    primaryHandle,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive2,
                    &inPublic2,
                    &outsideInfo2,
                    &creationPCR2,
                    &outPrivate2,
                    &outPublic2,
                    &creationData2, &creationHash2, &creationTicket2);

    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_Create Failed\n");
        return 1;
    }
    printf("Esys_Create Success.\n");
    printf("Key has been created.\n");



    /*
        Load key
    */
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;
    rc = Esys_Load(esysContext,
                  primaryHandle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE, outPrivate2, outPublic2, &loadedKeyHandle);
    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_Load Failed\n");
        return 1;
    }
    printf("Esys_Load Success.\n");
    printf("Key has been loaded.\n");

    rc = Esys_TR_SetAuth(esysContext, loadedKeyHandle, &authKey2);
    if (rc != TPM2_RC_SUCCESS) {
        printf("Third Esys_TR_SetAuth Failed\n");
        return 1;
    }
    printf("Third Esys_TR_SetAuth Success.\n");



    /* 
        Unseal key
    */
    TPM2B_SENSITIVE_DATA *outData = NULL;
    rc = Esys_Unseal(esysContext, loadedKeyHandle, ESYS_TR_PASSWORD,
            ESYS_TR_NONE, ESYS_TR_NONE, &outData);
    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_Unseal Failed\n");
        return 1;
    }
    printf("Esys_Unseal Success.\n");
    printf("Key has been unsealed.\n");

    printf("Unsealed Data: ");
    for (size_t i = 0; i < outData->size; i++) {
        printf("%02x", outData->buffer[i]);
    }
    printf("\n");
    


    if(memcmp(&(outData->buffer), &(inSensitive2.sensitive.data.buffer),
        inSensitive2.sensitive.data.size)!=0){
        printf("Unseal error, unequal.");
        return 1;
    }
    printf("Unsealed and sensitive data match correctly.\n");










    /*
        Sample text to encrypt and decrypt
    */ 
    unsigned char *plaintext = (unsigned char *)"Test text";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];
    unsigned char iv[AES_BLOCK_SIZE]; // Initialization vector
    memset(iv, 0x00, AES_BLOCK_SIZE); // Set IV to zeros for simplicity in this example

    // Encrypt the plaintext
    int ciphertext_len = encrypt(plaintext, strlen ((char *)plaintext), outData->buffer, iv, ciphertext);


    // Decrypt
    unsigned char plain[128];
    int plain_len = decrypt(ciphertext, ciphertext_len, outData->buffer, iv, plain);;


    printf("Plain text: %s\n", plaintext);
    printf("Ciphertext: %s\n", ciphertext);
    printf("Decrypted Data: %s\n", plain);









    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(outPrivate2);
    Esys_Free(outPublic2);
    Esys_Free(creationData2);
    Esys_Free(creationHash2);
    Esys_Free(creationTicket2);

    // Clear key memory and free it 
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_cleanse(outData->buffer, outData->size);
    Esys_Free(outData);

    Esys_FlushContext(esysContext, primaryHandle);
    Esys_FlushContext(esysContext, loadedKeyHandle);

    Esys_Finalize(&esysContext);







    return 0;

}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    /* Initialize encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
        return -1;

    /* Provide message to be encrypted, and get encrypted output. */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    /* Finalise encryption. */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    /* Create and initialize the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    /* Initialize the decryption operation. */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
        return -1;

    /* Provide ciphertext to be decrypted, and get plaintext output. */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    /* Finalize the decryption. */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        return -1;
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
