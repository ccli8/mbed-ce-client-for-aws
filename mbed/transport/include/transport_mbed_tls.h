/*
 * AWS IoT Device SDK for Embedded C 202012.01
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

#ifndef TRANSPORT_MBED_TLS_H
#define TRANSPORT_MBED_TLS_H

/* Mbed includes. */
#include "mbed.h"

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************/
/******* DO NOT CHANGE the following order ********/
/**************************************************/

/* Logging related header files are required to be included in the following order:
 * 1. Include the header file "logging_levels.h".
 * 2. Define LIBRARY_LOG_NAME and  LIBRARY_LOG_LEVEL.
 * 3. Include the header file "logging_stack.h".
 */

/* Include header that defines log levels. */
#include "logging_levels.h"

/* Logging configuration for the transport interface implementation which uses
 * TLSSocket. */
#ifndef LIBRARY_LOG_NAME
    #define LIBRARY_LOG_NAME     "Mbed_TLS_Socket"
#endif
#ifndef LIBRARY_LOG_LEVEL
    #define LIBRARY_LOG_LEVEL    LOG_ERROR
#endif

#include "logging_stack.h"

/************ End of logging configuration ****************/

/* Transport includes. */
#include "transport_mbed_base.h"

/* PSA includes */
#if COMPONENT_AWSIOT_PKCS11PSA
#include "psa/crypto.h"
#endif

/**
 * @brief Derived NetworkStruct for TLS
 */
struct TlsNetworkContext : public NetworkContext
{
    TlsNetworkContext() :
        socket(NULL)
#if COMPONENT_AWSIOT_PKCS11PSA
        , clientCrtInited(false)
        , clientKeyHandle(0)
        , clientkeyPKCtxInited(false)
#endif
    {
    }

    ~TlsNetworkContext()
    {
#if COMPONENT_AWSIOT_PKCS11PSA
        UninitClientCrtKey();
#endif
    }

#if COMPONENT_AWSIOT_PKCS11PSA
    void UninitClientCrtKey()
    {
        if (clientCrtInited) {
            mbedtls_x509_crt_free(&clientCrt);
            clientCrtInited = false;
        }
        if (clientKeyHandle) {
            psa_close_key(clientKeyHandle);
            clientKeyHandle = 0;
        }
        if (clientkeyPKCtxInited) {
            mbedtls_pk_free(&clientkeyPKCtx);
            clientkeyPKCtxInited = false;
        }
    }
#endif

    uint64_t                socketBlock[(sizeof(TLSSocket) + 7) / 8];
    TLSSocket *             socket;
#if COMPONENT_AWSIOT_PKCS11PSA
    /* TLSSocket hasn't supported opaque yet. Keep necessary context for
     * configuring mbedtls SSL straight */
    bool                    clientCrtInited;
    mbedtls_x509_crt        clientCrt;
    psa_key_id_t            clientKeyHandle;
    bool                    clientkeyPKCtxInited;
    mbedtls_pk_context      clientkeyPKCtx;
#endif
};
typedef struct TlsNetworkContext TlsNetworkContext_t;

/* The format for network credentials on this system. */
typedef struct {
    const uint8_t *rootCA;
    size_t rootCASize;
    const uint8_t *clientCrt;
    size_t clientCrtSize;
#if COMPONENT_AWSIOT_PKCS11PSA
    /* PSA client key ID */
    psa_key_id_t clientKeyId;
#endif
    const uint8_t *clientKey;
    size_t clientKeySize;
    
    /* Pointer to a NULL-terminated list of supported protocols,
     * in decreasing preference order. The pointer to the list is
     * recorded by the library for later reference as required, so
     * the lifetime of the table must be atleast as long as the
     * lifetime of the SSL configuration structure. */
    const char **alpnProtos;
} CredentialInfo_t;

/**
 * @brief Sets up a TLS session on top of a TCP connection.
 *
 * @param[out] pNetworkContext The output parameter to return the created network context.
 * @param[in] pServerInfo Server connection info.
 * @param[in] pCredentialInfo Credentials for the TLS connection.
 * @param[in] sendTimeoutMs Timeout for transport send.
 * @param[in] recvTimeoutMs Timeout for transport recv.
 *
 * @note A timeout of 0 means infinite timeout.
 *
 * @return 0 on success; -1 on failure
 */
int32_t Mbed_Tls_Connect( NetworkContext_t * pNetworkContext,
                          const ServerInfo_t * pServerInfo,
                          const CredentialInfo_t * pCredentialInfo,
                          uint32_t sendTimeoutMs,
                          uint32_t recvTimeoutMs );

/**
 * @brief Closes a TLS session on top of a TCP connection.
 *
 * @param[out] pNetworkContext The output parameter to end the TLS session and
 * clean the created network context.
 *
 * @return 0 on success; -1 on failure
 */
int32_t Mbed_Tls_Disconnect( NetworkContext_t * pNetworkContext );

/**
 * @brief Receives data over an established TLS session.
 *
 * This can be used as #TransportInterface.recv function for receiving data
 * from the network.
 *
 * @param[in] pNetworkContext The network context created using Mbed_Tls_Connect API.
 * @param[out] pBuffer Buffer to receive network data into.
 * @param[in] bytesToRecv Number of bytes requested from the network.
 *
 * @return Number of bytes received if successful; negative value to indicate failure.
 * A return value of zero represents that the receive operation can be retried.
 */
int32_t Mbed_Tls_Recv( NetworkContext_t * pNetworkContext,
                      void * pBuffer,
                      size_t bytesToRecv );

/**
 * @brief Sends data over an established TLS session.
 *
 * This can be used as the #TransportInterface.send function to send data
 * over the network.
 *
 * @param[in] pNetworkContext The network context created using Mbed_Tls_Connect API.
 * @param[in] pBuffer Buffer containing the bytes to send over the network stack.
 * @param[in] bytesToSend Number of bytes to send over the network.
 *
 * @return Number of bytes sent if successful; negative value on error.
 *
 * @note This function does not return zero value because it cannot be retried
 * on send operation failure.
 */
int32_t Mbed_Tls_Send( NetworkContext_t * pNetworkContext,
                      const void * pBuffer,
                      size_t bytesToSend );

#ifdef __cplusplus
}
#endif

#endif /* ifndef TRANSPORT_MBED_TLS_H */
