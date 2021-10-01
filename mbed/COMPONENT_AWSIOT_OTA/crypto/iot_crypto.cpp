/*
 * FreeRTOS Crypto V1.1.1
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

 /* C runtime includes. */
#include <string.h>
#include <stdbool.h>

/* Mbed includes. */
#include "mbed.h"
#include "mbed_trace.h"

/* mbedTLS includes. */
#if !defined( MBEDTLS_CONFIG_FILE )
    #include "mbedtls/config.h"
#else
    #include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha1.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/base64.h"
#include "mbedtls/rsa.h"
#include "mbedtls/asn1.h"
#include "mbed_error.h"

/* Threading mutex implementations for mbedTLS. */
#include "mbedtls/threading.h"

#if COMPONENT_AWSIOT_PKCS11PSA
/* PKCS#11 includes. */
#include "core_pkcs11_config.h"
#include "core_pkcs11.h"
#include "iot_pkcs11_psa_object_management.h"
#include "iot_pkcs11_psa_input_format.h"
#include "core_pki_utils.h"
#endif  /* #if COMPONENT_AWSIOT_PKCS11PSA */

#include "iot_crypto.h"

#define CRYPTO_PRINT( X )    printf X


/**
 * @brief Internal signature verification context structure
 */
typedef struct SignatureVerificationState
{
    uint8_t xAsymmetricAlgorithm;
    uint8_t xHashAlgorithm;
    mbedtls_sha1_context xSHA1Context;
    mbedtls_sha256_context xSHA256Context;

    /* Verify by signer certificate */
    const char * pcSignerCertificate;
    size_t xSignerCertificateLength;
#if COMPONENT_AWSIOT_PKCS11PSA
    /* Verify by PKCS11 public key label */
    const uint8_t * pcPKCS11PublicKeyLabel;
    size_t xPKCS11PublicKeyLabelLength;
    /* Verify by PSA public key ID */
    psa_key_id_t xPSAPublicKeyId;
#endif  /* #if COMPONENT_AWSIOT_PKCS11PSA */
} SignatureVerificationState_t, * SignatureVerificationStatePtr_t;

/*-----------------------------------------------------------*/
/*--------- mbedTLS threading functions for Mbed OS --------*/
/*--------- Set MBEDTLS_THREADING_ALT in PKCS11 module ------*/
/*-----------------------------------------------------------*/

/**
 * @brief Implementation of mbedtls_mutex_init for thread-safety.
 *
 */
void aws_mbedtls_mutex_init( mbedtls_threading_mutex_t * mutex )
{
    // ToDo: mutex->mutex = RTOS mutex create;

    if( mutex->mutex == NULL )
    {
         CRYPTO_PRINT( ( "Failed to initialize mbedTLS mutex.\r\n" ) );
    }
}

/**
 * @brief Implementation of mbedtls_mutex_free for thread-safety.
 *
 */
void aws_mbedtls_mutex_free( mbedtls_threading_mutex_t * mutex )
{
    if( mutex->mutex != NULL )
    {
        //ToDO: RTOS delete mutex
        mutex->mutex = NULL;
    }
}

/**
 * @brief Implementation of mbedtls_mutex_lock for thread-safety.
 *
 * @return 0 if successful, MBEDTLS_ERR_THREADING_MUTEX_ERROR if timeout,
 * MBEDTLS_ERR_THREADING_BAD_INPUT_DATA if the mutex is not valid.
 */
int aws_mbedtls_mutex_lock( mbedtls_threading_mutex_t * mutex )
{
    int ret = MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;

    if( mutex->mutex != NULL )
    {
        // ToDo: RTOS lock mutex
    }

    return ret;
}

/**
 * @brief Implementation of mbedtls_mutex_unlock for thread-safety.
 *
 * @return 0 if successful, MBEDTLS_ERR_THREADING_MUTEX_ERROR if timeout,
 * MBEDTLS_ERR_THREADING_BAD_INPUT_DATA if the mutex is not valid.
 */
int aws_mbedtls_mutex_unlock( mbedtls_threading_mutex_t * mutex )
{
    int ret = MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;

    if( mutex->mutex != NULL )
    {
        // ToDo: RTOS unlock mutex
    }

    return ret;
}

/*-----------------------------------------------------------*/

/**
 * @brief Verifies a cryptographic signature based on the signer
 * certificate, hash algorithm, and the data that was signed.
 */
static bool prvVerifySignatureByCertificate( const char * pcSignerCertificate,
                                             size_t xSignerCertificateLength,
                                             uint8_t xHashAlgorithm,
                                             uint8_t * pucHash,
                                             size_t xHashLength,
                                             uint8_t * pucSignature,
                                             size_t xSignatureLength )
{
    bool result = true;
    mbedtls_x509_crt xCertCtx;
    mbedtls_md_type_t xMbedHashAlg = MBEDTLS_MD_SHA256;


    memset( &xCertCtx, 0, sizeof( mbedtls_x509_crt ) );

    /*
     * Map the hash algorithm
     */
    if( cryptoHASH_ALGORITHM_SHA1 == xHashAlgorithm )
    {
        xMbedHashAlg = MBEDTLS_MD_SHA1;
    }

    /*
     * Decode and create a certificate context
     */
    mbedtls_x509_crt_init( &xCertCtx );

    if( 0 != mbedtls_x509_crt_parse(
            &xCertCtx, ( const unsigned char * ) pcSignerCertificate, xSignerCertificateLength ) )
    {
        result = false;
    }

    /*
     * Verify the signature using the public key from the decoded certificate
     */
    if( true == result )
    {
        if( 0 != mbedtls_pk_verify(
                &xCertCtx.pk,
                xMbedHashAlg,
                pucHash,
                xHashLength,
                pucSignature,
                xSignatureLength ) )
        {
            result = false;
        }
    }

    /*
     * Clean-up
     */
    mbedtls_x509_crt_free( &xCertCtx );

    return result;
}

#if COMPONENT_AWSIOT_PKCS11PSA

/**
 * @brief Verifies a cryptographic signature based on the PKCS11
 * public key label, hash algorithm, and the data that was signed.
 */
static bool prvVerifySignatureByPKCS11PublicKeyLabel( const uint8_t * pcPKCS11PublicKeyLabel,
                                                      size_t xPKCS11PublicKeyLabelLength,
                                                      uint8_t xHashAlgorithm,
                                                      uint8_t * pucHash,
                                                      size_t xHashLength,
                                                      uint8_t * pucSignature,
                                                      size_t xSignatureLength )
{
    bool result = false;

    CK_RV rc_pkcs11                         = CKR_OK;
    CK_FUNCTION_LIST_PTR pxFunctionList     = NULL;
    CK_SESSION_HANDLE xSession              = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xCodeVerifyKey         = CK_INVALID_HANDLE;
    CK_MECHANISM mechanism_RSA              = { CKM_RSA_X_509, NULL, 0 };
    CK_MECHANISM mechanism_ECDSA            = { CKM_ECDSA, NULL, 0 };
    CK_MECHANISM *pMechanism;

    rc_pkcs11 = C_GetFunctionList(&pxFunctionList);
    if (CKR_OK != rc_pkcs11) {
        CRYPTO_PRINT( ( "C_GetFunctionList failed: %lu\r\n", rc_pkcs11 ) );
        goto cleanup3;
    }

    rc_pkcs11 = xInitializePKCS11();
    if (CKR_OK != rc_pkcs11) {
        CRYPTO_PRINT( ( "xInitializePKCS11 failed: %lu\r\n", rc_pkcs11 ) );
        goto cleanup3;
    }

    rc_pkcs11 = xInitializePkcs11Token();
    if (CKR_OK != rc_pkcs11) {
        CRYPTO_PRINT( ( "xInitializePkcs11Token failed: %lu\r\n", rc_pkcs11 ) );
        goto cleanup2;
    }

    rc_pkcs11 = xInitializePkcs11Session(&xSession);
    if (CKR_OK != rc_pkcs11) {
        CRYPTO_PRINT( ( "xInitializePkcs11Session failed: %lu\r\n", rc_pkcs11 ) );
        goto cleanup2;
    }

    rc_pkcs11 = xFindObjectWithLabelAndClass(xSession,
                                             (char *) pcPKCS11PublicKeyLabel,
                                             xPKCS11PublicKeyLabelLength,
                                             CKO_PUBLIC_KEY,
                                             &xCodeVerifyKey);
    if (CKR_OK != rc_pkcs11) {
        CRYPTO_PRINT( ( "xFindObjectWithLabelAndClass failed: %lu\r\n", rc_pkcs11 ) );
        goto cleanup1;
    }

    /* Iterate over RSA/ECDSA for matched mechanism/key */
    pMechanism = &mechanism_RSA;
    rc_pkcs11 = pxFunctionList->C_VerifyInit(xSession,
                                             pMechanism,
                                             xCodeVerifyKey);
    if (CKR_KEY_TYPE_INCONSISTENT == rc_pkcs11) {
        CRYPTO_PRINT( ( "Key not RSA type. Try ECC...\r\n" ) );
        pMechanism = &mechanism_ECDSA;
        rc_pkcs11 = pxFunctionList->C_VerifyInit(xSession,
                                                 pMechanism,
                                                 xCodeVerifyKey);
    }
    if (CKR_OK != rc_pkcs11) {
        CRYPTO_PRINT( ( "C_VerifyInit failed: %lu\r\n", rc_pkcs11 ) );
        goto cleanup1;
    }

    /* For ECC, convert from mbedtls signature to pkcs11/psa signature */
    if (pMechanism == &mechanism_ECDSA) {
        /* This error code will update on calling signature verification
         * function, or remains. */
        rc_pkcs11 = CKR_VENDOR_DEFINED;

        /* Over-allocate pkcs signature buffer using mbedtls signature length */
        size_t xPKCSSignatureLength = xSignatureLength;
        uint8_t *pucPKCSSignature = (uint8_t *) malloc(xPKCSSignatureLength);

        /* NOTE: PKI_mbedTLSSignatureToPkcs11Signature/PKI_pkcs11SignatureTombedTLSSignature
         *       should have enhanced to support beyond ECC P-256. */
        if (0 != PKI_mbedTLSSignatureToPkcs11Signature(pucPKCSSignature,
                                                       &xPKCSSignatureLength,
                                                       pucSignature,
                                                       xSignatureLength)) {
            CRYPTO_PRINT( ( "PKI_mbedTLSSignatureToPkcs11Signature failed\r\n" ) );
            goto cleanup_pkcssig;
        }
                                
        rc_pkcs11 = pxFunctionList->C_Verify(xSession,
                                             pucHash,
                                             xHashLength,
                                             pucPKCSSignature,
                                             xPKCSSignatureLength);

cleanup_pkcssig:
        if (pucPKCSSignature) {
            free(pucPKCSSignature);
            pucPKCSSignature = NULL;
        }
    } else {
        rc_pkcs11 = pxFunctionList->C_Verify(xSession,
                                             pucHash,
                                             xHashLength,
                                             pucSignature,
                                             xSignatureLength);
    }
    if (CKR_OK != rc_pkcs11) {
        CRYPTO_PRINT( ( "C_Verify failed: %lu\r\n", rc_pkcs11 ) );
        goto cleanup1;
    }

    result = true;

cleanup1:
    pxFunctionList->C_CloseSession(xSession);

cleanup2:
    pxFunctionList->C_Finalize(NULL);

cleanup3:
    return result;
}

/**
 * @brief Verifies a cryptographic signature based on the PSA
 * public key ID, hash algorithm, and the data that was signed.
 */
static bool prvVerifySignatureByPSAPublicKeyID( psa_key_id_t xPSAPublicKeyId,
                                                uint8_t xHashAlgorithm,
                                                uint8_t * pucHash,
                                                size_t xHashLength,
                                                uint8_t * pucSignature,
                                                size_t xSignatureLength )
{
    bool result = false;
    psa_status_t rc_psa = PSA_SUCCESS;
    psa_key_id_t pubkey_handle = 0;
    psa_key_attributes_t pubkey_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t pubkey_alg;
    psa_algorithm_t sha_alg;

    rc_psa = psa_open_key(xPSAPublicKeyId, &pubkey_handle);
    if (PSA_SUCCESS != rc_psa) {
        CRYPTO_PRINT( ( "psa_open_key(%d) failed: %d\r\n", xPSAPublicKeyId, rc_psa ) );
        goto cleanup2;
    }

    rc_psa = psa_get_key_attributes(pubkey_handle, &pubkey_attributes);
    if (PSA_SUCCESS != rc_psa) {
        CRYPTO_PRINT( ( "psa_get_key_attributes failed: %d\r\n", rc_psa ) );
        goto cleanup1;
    }

    pubkey_alg = psa_get_key_algorithm(&pubkey_attributes);
    sha_alg = (xHashAlgorithm == cryptoHASH_ALGORITHM_SHA1) ? PSA_ALG_SHA_1 : PSA_ALG_SHA_256;

    if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(pubkey_alg)) {
        pubkey_alg = PSA_ALG_RSA_PKCS1V15_SIGN(sha_alg);
    } else if (PSA_ALG_IS_RSA_PSS(pubkey_alg)) {
        pubkey_alg = PSA_ALG_RSA_PSS(sha_alg);
    } else if (PSA_ALG_IS_ECDSA(pubkey_alg)) {
        pubkey_alg = PSA_ALG_ECDSA(sha_alg);
    } else {
        CRYPTO_PRINT( ( "Unsupported PSA algorithm: 0x%08x\r\n", pubkey_alg ) );
        goto cleanup1;
    }

    /* For ECC, convert from mbedtls signature to pkcs11/psa signature */
    if (PSA_ALG_IS_ECDSA(pubkey_alg)) {
        /* This error code will update on calling signature verification
         * function, or remains. */
        rc_psa = PSA_ERROR_GENERIC_ERROR;

        /* Over-allocate pkcs signature buffer using mbedtls signature length */
        size_t xPKCSSignatureLength = xSignatureLength;
        uint8_t *pucPKCSSignature = (uint8_t *) malloc(xPKCSSignatureLength);

        /* NOTE: PKI_mbedTLSSignatureToPkcs11Signature/PKI_pkcs11SignatureTombedTLSSignature
         *       should have enhanced to support beyond ECC P-256. */
        if (0 != PKI_mbedTLSSignatureToPkcs11Signature(pucPKCSSignature,
                                                       &xPKCSSignatureLength,
                                                       pucSignature,
                                                       xSignatureLength)) {
            CRYPTO_PRINT( ( "PKI_mbedTLSSignatureToPkcs11Signature failed\r\n" ) );
            goto cleanup_pkcssig;
        }
                                   
        rc_psa = psa_verify_hash(pubkey_handle,
                                 pubkey_alg,
                                 pucHash,
                                 xHashLength,
                                 pucPKCSSignature,
                                 xPKCSSignatureLength);

cleanup_pkcssig:
        if (pucPKCSSignature) {
            free(pucPKCSSignature);
            pucPKCSSignature = NULL;
        }
    } else {
        rc_psa = psa_verify_hash(pubkey_handle,
                                 pubkey_alg,
                                 pucHash,
                                 xHashLength,
                                 pucSignature,
                                 xSignatureLength);
    }
    if (PSA_SUCCESS != rc_psa) {
        CRYPTO_PRINT( ( "psa_verify_hash failed: %d\r\n", rc_psa ) );
        goto cleanup1;
    }

    result = true;

cleanup1:
    psa_close_key(pubkey_handle);

cleanup2:
    return result;
}

#endif  /* #if COMPONENT_AWSIOT_PKCS11PSA */

/**
 * @brief Performs signature verification on a cryptographic hash.
 */
static bool CRYPTO_SignatureVerificationFinalCommon( void * pvContext,
                                                     uint8_t * pucSignature,
                                                     size_t xSignatureLength )
{
    bool result = false;

    if( pvContext != NULL )
    {
        SignatureVerificationStatePtr_t pxCtx = ( SignatureVerificationStatePtr_t ) pvContext; /*lint !e9087 Allow casting void* to other types. */
        uint8_t ucSHA1or256[ cryptoSHA256_DIGEST_BYTES ];                                      /* Reserve enough space for the larger of SHA1 or SHA256 results. */
        uint8_t * pucHash = NULL;
        size_t xHashLength = 0;

        if( ( pucSignature != NULL ) &&
            ( xSignatureLength > 0UL ) )
        {
            /*
             * Finish the hash
             */
            if( cryptoHASH_ALGORITHM_SHA1 == pxCtx->xHashAlgorithm )
            {
                ( void ) mbedtls_sha1_finish_ret( &pxCtx->xSHA1Context, ucSHA1or256 );
                pucHash = ucSHA1or256;
                xHashLength = cryptoSHA1_DIGEST_BYTES;
            }
            else
            {
                ( void ) mbedtls_sha256_finish_ret( &pxCtx->xSHA256Context, ucSHA1or256 );
                pucHash = ucSHA1or256;
                xHashLength = cryptoSHA256_DIGEST_BYTES;
            }

            /*
             * Verify the signature
             */
            if (pxCtx->pcSignerCertificate && pxCtx->xSignerCertificateLength) {
                result = prvVerifySignatureByCertificate( pxCtx->pcSignerCertificate,
                                                          pxCtx->xSignerCertificateLength,
                                                          pxCtx->xHashAlgorithm,
                                                          pucHash,
                                                          xHashLength,
                                                          pucSignature,
                                                          xSignatureLength );
#if COMPONENT_AWSIOT_PKCS11PSA
            } else if (pxCtx->pcPKCS11PublicKeyLabel && pxCtx->xPKCS11PublicKeyLabelLength) {
                result = prvVerifySignatureByPKCS11PublicKeyLabel( pxCtx->pcPKCS11PublicKeyLabel,
                                                                   pxCtx->xPKCS11PublicKeyLabelLength,
                                                                   pxCtx->xHashAlgorithm,
                                                                   pucHash,
                                                                   xHashLength,
                                                                   pucSignature,
                                                                   xSignatureLength );
            } else if (pxCtx->xPSAPublicKeyId) {
                result = prvVerifySignatureByPSAPublicKeyID( pxCtx->xPSAPublicKeyId,
                                                             pxCtx->xHashAlgorithm,
                                                             pucHash,
                                                             xHashLength,
                                                             pucSignature,
                                                             xSignatureLength );
#endif  /* #if COMPONENT_AWSIOT_PKCS11PSA */
            } else {
                result = false;
            }
        }
        else
        {
            /* Allow function to be called with only the context pointer for cleanup after a failure. */
        }

        /*
         * Clean-up
         */
        free( pxCtx );
    }

    return result;
}

void CRYPTO_ConfigureThreading( void )
{
    /* Configure mbedtls to use Mbed-OS mutexes. */
    mbedtls_threading_set_alt( aws_mbedtls_mutex_init,
                               aws_mbedtls_mutex_free,
                               aws_mbedtls_mutex_lock,
                               aws_mbedtls_mutex_unlock );
}

/*
 * Interface routines
 */

void CRYPTO_Init( void )
{
    // Already configure threading in PKCS11 module, so not call mbedtls_threading_set_alt() here
    // CRYPTO_ConfigureThreading();

#if COMPONENT_AWSIOT_PKCS11PSA
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        MBED_ERROR1(MBED_MAKE_ERROR(MBED_MODULE_APPLICATION, MBED_ERROR_CODE_INITIALIZATION_FAILED),
                    "psa_crypto_init() failed: ",
                    status);
    }
#endif  /* #if COMPONENT_AWSIOT_PKCS11PSA */
}

/**
 * @brief Creates signature verification context.
 */
bool CRYPTO_SignatureVerificationStart( void ** ppvContext,
                                              uint8_t xAsymmetricAlgorithm,
                                              uint8_t xHashAlgorithm )
{
    bool result = true;
    SignatureVerificationState_t * pxCtx = NULL;

    /*
     * Allocate the context
     */
    if( NULL == ( pxCtx = ( SignatureVerificationStatePtr_t ) malloc(
                      sizeof( *pxCtx ) ) ) ) /*lint !e9087 Allow casting void* to other types. */
    {
        result = false;
    }

    if( result == true )
    {
        /* Clean, zero-initialized context, necessary for resolving which signature
         * verification approach to go in CRYPTO_SignatureVerificationFinalCommon */
        memset(pxCtx, 0x00, sizeof(*pxCtx));

        *ppvContext = pxCtx;

        /*
         * Store the algorithm identifiers
         */
        pxCtx->xAsymmetricAlgorithm = xAsymmetricAlgorithm;
        pxCtx->xHashAlgorithm = xHashAlgorithm;

        /*
         * Initialize the requested hash type
         */
        if( cryptoHASH_ALGORITHM_SHA1 == pxCtx->xHashAlgorithm )
        {
            mbedtls_sha1_init( &pxCtx->xSHA1Context );
            ( void ) mbedtls_sha1_starts_ret( &pxCtx->xSHA1Context );
        }
        else
        {
            mbedtls_sha256_init( &pxCtx->xSHA256Context );
            ( void ) mbedtls_sha256_starts_ret( &pxCtx->xSHA256Context, 0 );
        }
    }

    return result;
}

/**
 * @brief Adds bytes to an in-progress hash for subsequent signature
 * verification.
 */
void CRYPTO_SignatureVerificationUpdate( void * pvContext,
                                         const uint8_t * pucData,
                                         size_t xDataLength )
{
    SignatureVerificationState_t * pxCtx = ( SignatureVerificationStatePtr_t ) pvContext; /*lint !e9087 Allow casting void* to other types. */

    /*
     * Add the data to the hash of the requested type
     */
    if( cryptoHASH_ALGORITHM_SHA1 == pxCtx->xHashAlgorithm )
    {
        ( void ) mbedtls_sha1_update_ret( &pxCtx->xSHA1Context, pucData, xDataLength );
    }
    else
    {
        ( void ) mbedtls_sha256_update_ret( &pxCtx->xSHA256Context, pucData, xDataLength );
    }
}

/**
 * @brief Performs signature verification on a cryptographic hash.
 */
bool CRYPTO_SignatureVerificationFinal( void * pvContext,
                                        const char * pcSignerCertificate,
                                        size_t xSignerCertificateLength,
                                        uint8_t * pucSignature,
                                        size_t xSignatureLength )
{
    if (pvContext != NULL) {
        SignatureVerificationStatePtr_t pxCtx = (SignatureVerificationStatePtr_t) pvContext;
        pxCtx->pcSignerCertificate = pcSignerCertificate;
        pxCtx->xSignerCertificateLength = xSignerCertificateLength;
        return CRYPTO_SignatureVerificationFinalCommon(pvContext, pucSignature, xSignatureLength);
    } else {
        return false;
    }
}

#if COMPONENT_AWSIOT_PKCS11PSA

/**
 * @brief Variant of CRYPTO_SignatureVerificationFinal, using PKCS11 public key label.
 */
bool CRYPTO_SignatureVerificationFinalByPKCS11Label( void * pvContext,
                                                     const uint8_t * pcPKCS11PublicKeyLabel,
                                                     size_t xPKCS11PublicKeyLabelLength,
                                                     uint8_t * pucSignature,
                                                     size_t xSignatureLength )
{
    if (pvContext != NULL) {
        SignatureVerificationStatePtr_t pxCtx = (SignatureVerificationStatePtr_t) pvContext;
        pxCtx->pcPKCS11PublicKeyLabel = pcPKCS11PublicKeyLabel;
        pxCtx->xPKCS11PublicKeyLabelLength = xPKCS11PublicKeyLabelLength;
        return CRYPTO_SignatureVerificationFinalCommon(pvContext, pucSignature, xSignatureLength);
    } else {
        return false;
    }
}

/**
 * @brief Variant of CRYPTO_SignatureVerificationFinal, using PSA public key ID.
 */
bool CRYPTO_SignatureVerificationFinalByPSAKeyId( void * pvContext,
                                                  psa_key_id_t xPSAPublicKeyId,
                                                  uint8_t * pucSignature,
                                                  size_t xSignatureLength )
{
    if (pvContext != NULL) {
        SignatureVerificationStatePtr_t pxCtx = (SignatureVerificationStatePtr_t) pvContext;
        pxCtx->xPSAPublicKeyId = xPSAPublicKeyId;
        return CRYPTO_SignatureVerificationFinalCommon(pvContext, pucSignature, xSignatureLength);
    } else {
        return false;
    }
}

#endif  /* #if COMPONENT_AWSIOT_PKCS11PSA */
