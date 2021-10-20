/*
 * OTA PAL V2.0.0 (Release Candidate) for POSIX
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
 */

/**
 * @file core_pkcs11_pal.c
 * @brief Mbed KVStore save and read implementation
 * for PKCS #11 based on mbedTLS with for software keys. This
 * file deviates from the FreeRTOS style standard for some function names and
 * data types in order to maintain compliance with the PKCS #11 standard.
 */
/*-----------------------------------------------------------*/

/* Mbed includes */
#include "mbed.h"
#include "kvstore_global_api.h"
/* Get around macro redefinition */
#undef TRUE
#undef FALSE

/* PKCS 11 includes. */
extern "C" {
#include "core_pkcs11_config.h"
#include "core_pkcs11.h"
#include "core_pkcs11_pal.h"
}

/* C runtime includes. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @ingroup pkcs11_macros
 * @brief Macros for managing PKCS #11 objects in flash.
 *
 */
#define pkcs11palLABEL_ROOT_CERTIFICATE             "/" STR(MBED_CONF_STORAGE_DEFAULT_KV) "/" pkcs11configLABEL_ROOT_CERTIFICATE              /**< The KVStore key name of the Root CA Certificate object. */
#define pkcs11palLABEL_DEVICE_CERTIFICATE_FOR_TLS   "/" STR(MBED_CONF_STORAGE_DEFAULT_KV) "/" pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS    /**< The KVStore key name of the Device Certificate object. */
#define pkcs11palLABEL_DEVICE_PUBLIC_KEY_FOR_TLS    "/" STR(MBED_CONF_STORAGE_DEFAULT_KV) "/" pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS     /**< The KVStore key name of the Device Public Key object. */
#define pkcs11palLABEL_DEVICE_PRIVATE_KEY_FOR_TLS   "/" STR(MBED_CONF_STORAGE_DEFAULT_KV) "/" pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS    /**< The KVStore key name of the Device Private Key object. */
#define pkcs11palLABEL_CODE_VERIFICATION_KEY        "/" STR(MBED_CONF_STORAGE_DEFAULT_KV) "/" pkcs11configLABEL_CODE_VERIFICATION_KEY         /**< The KVStore key name of the Code Signing Certificate object. */

/**
 * @ingroup pkcs11_enums
 * @brief Enums for managing PKCS #11 object types.
 *
 */
enum eObjectHandles
{
    eInvalidHandle = 0,         /**< According to PKCS #11 spec, 0 is never a valid object handle. */
    eAwsRootCACertificate,      /**< Root CA Certificate. */
    eAwsDeviceCertificate,      /**< Device Certificate. */
    eAwsDevicePublicKey,        /**< Device Public Key. */
    eAwsDevicePrivateKey,       /**< Device Private Key. */
    eAwsCodeSigningKey          /**< Code Signing Key. */
};

/*-----------------------------------------------------------*/

/* Stringize */
#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

/*-----------------------------------------------------------*/

/**
 * @brief Checks to see if a KVStore key exists
 *
 * @param[in] pcKeyName         The KVStore key name to check for existence.
 *
 * @returns CKR_OK if the key exists, CKR_OBJECT_HANDLE_INVALID if not.
 */
static CK_RV prvKeyExists( const char * pcFqKeyName )
{
    CK_RV xReturn = CKR_OK;

    kv_info_t info;
    auto kv_status = kv_get_info(pcFqKeyName, &info);
    if (kv_status != MBED_SUCCESS) {
        xReturn = CKR_OBJECT_HANDLE_INVALID;
        LogError( ("kv_get_info: %s failed: %d", pcFqKeyName, MBED_GET_ERROR_CODE(kv_status)) );
    } else {
        LogDebug( ( "Found key %s and was able to get it for reading.", pcFqKeyName) );
    }

    return xReturn;
}

/**
 * @brief Map PKCS #11 label to KVStore key name
 *
 * @param[in] pcLabel            The PKCS #11 label to convert to a KVStore key name.
 * @param[out] pcFqKeyName       The name of the KVStore key name to check for existence.
 * @param[out] pHandle           The type of the PKCS #11 object.
 *
 */
static void prvLabelToKeynameHandle( const char * pcLabel,
                                     const char ** pcFqKeyName,
                                     CK_OBJECT_HANDLE_PTR pHandle )
{
    if( ( pcLabel != NULL ) && ( pHandle != NULL ) && ( pcFqKeyName != NULL ) )
    {
        if( 0 == strncmp( pkcs11configLABEL_ROOT_CERTIFICATE,
                          pcLabel,
                          sizeof( pkcs11configLABEL_ROOT_CERTIFICATE ) ) )
        {
            *pcFqKeyName = pkcs11palLABEL_ROOT_CERTIFICATE;
            *pHandle = ( CK_OBJECT_HANDLE ) eAwsRootCACertificate;
        }
        else if( 0 == strncmp( pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                          pcLabel,
                          sizeof( pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS ) ) )
        {
            *pcFqKeyName = pkcs11palLABEL_DEVICE_CERTIFICATE_FOR_TLS;
            *pHandle = ( CK_OBJECT_HANDLE ) eAwsDeviceCertificate;
        }
        else if( 0 == strncmp( pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                               pcLabel,
                               sizeof( pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS ) ) )
        {
            *pcFqKeyName = pkcs11palLABEL_DEVICE_PUBLIC_KEY_FOR_TLS;
            *pHandle = ( CK_OBJECT_HANDLE ) eAwsDevicePublicKey;
        }
        else if( 0 == strncmp( pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                               pcLabel,
                               sizeof( pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) ) )
        {
            *pcFqKeyName = pkcs11palLABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
            *pHandle = ( CK_OBJECT_HANDLE ) eAwsDevicePrivateKey;
        }
        else if( 0 == strncmp( pkcs11configLABEL_CODE_VERIFICATION_KEY,
                               pcLabel,
                               sizeof( pkcs11configLABEL_CODE_VERIFICATION_KEY ) ) )
        {
            *pcFqKeyName = pkcs11palLABEL_CODE_VERIFICATION_KEY;
            *pHandle = ( CK_OBJECT_HANDLE ) eAwsCodeSigningKey;
        }
        else
        {
            *pcFqKeyName = NULL;
            *pHandle = ( CK_OBJECT_HANDLE ) eInvalidHandle;
        }

        LogDebug( ( "Converted %s to %s", pcLabel, *pcFqKeyName ) );
    }
    else
    {
        LogError( ( "Could not convert label to KVStore key name. Received a NULL parameter." ) );
    }
}

/**
 * @brief Maps object handle to KVStore key name
 *
 * @param[in] xHandle           The type of the PKCS #11 object.
 * @param[out] pcLabel          The PKCS #11 label to convert to a KVStore key name
 * @param[out] pIsPrivate       Private or not
 *
 */
static CK_RV prvHandleToKeyname( CK_OBJECT_HANDLE xHandle,
                                 const char ** pcFqKeyName,
                                 CK_BBOOL * pIsPrivate )
{
    CK_RV xReturn = CKR_OK;

    if( pcFqKeyName != NULL )
    {
        switch( ( CK_OBJECT_HANDLE ) xHandle )
        {
            case eAwsRootCACertificate:
                *pcFqKeyName = pkcs11palLABEL_ROOT_CERTIFICATE;
                /* coverity[misra_c_2012_rule_10_5_violation] */
                *pIsPrivate = ( CK_BBOOL ) CK_FALSE;
                break;

            case eAwsDeviceCertificate:
                *pcFqKeyName = pkcs11palLABEL_DEVICE_CERTIFICATE_FOR_TLS;
                /* coverity[misra_c_2012_rule_10_5_violation] */
                *pIsPrivate = ( CK_BBOOL ) CK_FALSE;
                break;

            case eAwsDevicePublicKey:
                *pcFqKeyName = pkcs11palLABEL_DEVICE_PUBLIC_KEY_FOR_TLS;
                /* coverity[misra_c_2012_rule_10_5_violation] */
                *pIsPrivate = ( CK_BBOOL ) CK_FALSE;
                break;

            case eAwsDevicePrivateKey:
                *pcFqKeyName = pkcs11palLABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
                /* coverity[misra_c_2012_rule_10_5_violation] */
                *pIsPrivate = ( CK_BBOOL ) CK_TRUE;
                break;

            case eAwsCodeSigningKey:
                *pcFqKeyName = pkcs11palLABEL_CODE_VERIFICATION_KEY;
                /* coverity[misra_c_2012_rule_10_5_violation] */
                *pIsPrivate = ( CK_BBOOL ) CK_FALSE;
                break;

            default:
                xReturn = CKR_KEY_HANDLE_INVALID;
                break;
        }
    }
    else
    {
        LogError( ( "Could not convert label to KVStore key name. Received a NULL parameter." ) );
    }

    return xReturn;
}

/**
 * @brief Reads object value from KVStore.
 *
 * @param[out] pcFqKeyName       The name of the KVStore key name
 *
 */
static CK_RV prvReadData( const char * pcFqKeyName,
                          CK_BYTE_PTR * ppucData,
                          CK_ULONG_PTR pulDataSize )
{
    CK_RV xReturn = CKR_OK;
    size_t lSize = 0;

    kv_info_t info;
    auto kv_status = kv_get_info(pcFqKeyName, &info);

    if( MBED_SUCCESS != kv_status )
    {
        LogError( ( "PKCS #11 PAL failed to get object value. "
                    "Could not kv_get_info %s for reading.", pcFqKeyName ) );
        xReturn = CKR_FUNCTION_FAILED;
    }
    else
    {
        lSize = info.size;

        if( lSize > 0UL )
        {
            *pulDataSize = lSize;
            *ppucData = (CK_BYTE_PTR) malloc( *pulDataSize );

            if( NULL == *ppucData )
            {
                LogError( ( "Could not get object value. Malloc failed to allocate memory." ) );
                xReturn = CKR_HOST_MEMORY;
            }
        }
        else
        {
            LogError( ( "Could not get object value. Failed to determine object size." ) );
            xReturn = CKR_FUNCTION_FAILED;
        }
    }

    if( CKR_OK == xReturn )
    {
        lSize = 0;
        kv_status = kv_get(pcFqKeyName, *ppucData, *pulDataSize, &lSize);

        if( lSize != *pulDataSize )
        {
            LogError( ( "PKCS #11 PAL Failed to get object value. Expected to read %ld "
                        "from %s but received %ld", *pulDataSize, pcFqKeyName, lSize ) );
            xReturn = CKR_FUNCTION_FAILED;
        }
    }

    return xReturn;
}

/*-----------------------------------------------------------*/

CK_RV PKCS11_PAL_Initialize( void )
{
    return CKR_OK;
}

CK_OBJECT_HANDLE PKCS11_PAL_SaveObject( CK_ATTRIBUTE_PTR pxLabel,
                                        CK_BYTE_PTR pucData,
                                        CK_ULONG ulDataSize )
{
    size_t ulBytesWritten;
    const char * pcFqKeyName = NULL;
    CK_OBJECT_HANDLE xHandle = ( CK_OBJECT_HANDLE ) eInvalidHandle;

    if( ( pxLabel != NULL ) && ( pucData != NULL ) )
    {
        /* Converts a label to its respective KVStore key name and handle. */
        prvLabelToKeynameHandle( (const char *) pxLabel->pValue,
                                  &pcFqKeyName,
                                  &xHandle );
    }
    else
    {
        LogError( ( "Could not save object. Received invalid parameters." ) );
    }

    if( pcFqKeyName != NULL )
    {
        /* Overwrite the key every time it is saved. */

        {
            kv_set(pcFqKeyName, pucData, ulDataSize, 0);
            kv_info_t info;
            kv_get_info(pcFqKeyName, &info);
            ulBytesWritten = info.size;
        
            if( ulBytesWritten != ulDataSize )
            {
                LogError( ( "PKCS #11 PAL was unable to save object to KVStore. "
                            "Expected to write %lu bytes, but wrote %lu bytes.", ulDataSize, ulBytesWritten ) );
                xHandle = ( CK_OBJECT_HANDLE ) eInvalidHandle;
            }
            else
            {
                LogDebug( ( "Successfully wrote %lu to %s", ulBytesWritten, pcFqKeyName ) );
            }
        }
    }
    else
    {
        LogError( ( "Could not save object. Unable to find the correct KVStore key." ) );
    }

    return xHandle;
}

/*-----------------------------------------------------------*/


CK_OBJECT_HANDLE PKCS11_PAL_FindObject( CK_BYTE_PTR pxLabel,
                                        CK_ULONG usLength )
{
    const char * pcFqKeyName = NULL;
    CK_OBJECT_HANDLE xHandle = ( CK_OBJECT_HANDLE ) eInvalidHandle;

    ( void ) usLength;

    if( pxLabel != NULL )
    {
        prvLabelToKeynameHandle( ( const char * ) pxLabel,
                                  &pcFqKeyName,
                                  &xHandle );

        if( CKR_OK != prvKeyExists( pcFqKeyName ) )
        {
            xHandle = ( CK_OBJECT_HANDLE ) eInvalidHandle;
        }
    }
    else
    {
        LogError( ( "Could not find object. Received a NULL label." ) );
    }

    return xHandle;
}
/*-----------------------------------------------------------*/

CK_RV PKCS11_PAL_GetObjectValue( CK_OBJECT_HANDLE xHandle,
                                 CK_BYTE_PTR * ppucData,
                                 CK_ULONG_PTR pulDataSize,
                                 CK_BBOOL * pIsPrivate )
{
    CK_RV xReturn = CKR_OK;
    const char * pcFqKeyName = NULL;


    if( ( ppucData == NULL ) || ( pulDataSize == NULL ) || ( pIsPrivate == NULL ) )
    {
        xReturn = CKR_ARGUMENTS_BAD;
        LogError( ( "Could not get object value. Received a NULL argument." ) );
    }
    else
    {
        xReturn = prvHandleToKeyname( xHandle, &pcFqKeyName, pIsPrivate );
    }

    if( xReturn == CKR_OK )
    {
        xReturn = prvReadData( pcFqKeyName, ppucData, pulDataSize );
    }

    return xReturn;
}

/*-----------------------------------------------------------*/

void PKCS11_PAL_GetObjectValueCleanup( CK_BYTE_PTR pucData,
                                       CK_ULONG ulDataSize )
{
    /* Unused parameters. */
    ( void ) ulDataSize;

    if( NULL != pucData )
    {
        free( pucData );
    }
}

/*-----------------------------------------------------------*/

CK_RV PKCS11_PAL_DestroyObject( CK_OBJECT_HANDLE xHandle )
{
    const char * pcFqKeyName = NULL;
    CK_BBOOL xIsPrivate = CK_TRUE;
    CK_RV xResult = CKR_OBJECT_HANDLE_INVALID;
    int ret = 0;

    xResult = prvHandleToKeyname( xHandle,
                                  &pcFqKeyName,
                                  &xIsPrivate );

    if( ( xResult == CKR_OK ) && ( prvKeyExists( pcFqKeyName ) == CKR_OK ) )
    {
        auto kv_status = kv_remove( pcFqKeyName );

        if( kv_status != MBED_SUCCESS )
        {
            LogError( ( "PKCS #11 PAL failed to destroy object. "
                    "Could not kv_remove %s.", pcFqKeyName ) );
            xResult = CKR_FUNCTION_FAILED;
        }
    }

    return xResult;
}

/*-----------------------------------------------------------*/
