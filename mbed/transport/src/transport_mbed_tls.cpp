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

/* Standard includes. */
#include <assert.h>
#include <string.h>

/* Transport includes. */
#include "transport_mbed_tls.h"

int32_t Mbed_Tls_Connect( NetworkContext_t * pNetworkContext,
                          const ServerInfo_t * pServerInfo,
                          const CredentialInfo_t * pCredentialInfo,
                          uint32_t sendTimeoutMs,
                          uint32_t recvTimeoutMs )
{
    /* Validate parameters. */
    if (pNetworkContext == NULL) {
        LogError(("Parameter check failed: pNetworkContext is NULL."));
        return -1;
    } else if (pServerInfo == NULL || pServerInfo->hostname == NULL) {
        LogError(("Parameter check failed: pServerInfo or its hostname is NULL."));
        return -1;
    }

    /* Default network interface */
    auto net = NetworkInterface::get_default_instance();
    if (net == NULL) {
        LogError(("Default network interface is NULL."));
        return -1;
    }

    /* Cast 'pNetworkContext' to 'TlsNetworkContext_t *' for following net socket operations */
    auto *ctx_ = static_cast<TlsNetworkContext_t *>(static_cast<void *>(pNetworkContext));

    /* Save send/recv timeout */
    ctx_->sendTimeoutMs = sendTimeoutMs;
    ctx_->recvTimeoutMs = recvTimeoutMs;

    /* Check un-closed connection */
    if (ctx_->socket) {
        LogWarn(("Socket control block un-closed but reused for new connection. Close previous connection first."));
        ctx_->socket->~TLSSocket();
        ctx_->socket = NULL;
    }

    /* Construct socket */
    ctx_->socket = new (ctx_->socketBlock) TLSSocket;

    nsapi_size_or_error_t rc;
    SocketAddress sockaddr;

    /* AWS IoT requires devices to send the Server Name Indication (SNI)
     * extension to the Transport Layer Security (TLS) protocol and provide
     * the complete endpoint address in the host_name field. Details about
     *
     * This call will direct to mbedtls_ssl_set_hostname(...), which will also
     * set the SNI extension if enabled.
     *
     * For details regarding SNI, refer to:
     * https://www.globalsign.com/en/blog/what-is-server-name-indication
     */
    ctx_->socket->set_hostname(pServerInfo->hostname);

    /* Configure root CA into TLSSocket */
    if (pCredentialInfo && pCredentialInfo->rootCA && pCredentialInfo->rootCASize) {
        rc = ctx_->socket->set_root_ca_cert(pCredentialInfo->rootCA, pCredentialInfo->rootCASize);
        if (rc != 0) {
            LogError(("Error: configure root CA into TLSSocket: %d", rc));
            goto cleanup;
        }
    }

    /* Configure client certificate/private key into TLSSocket */
    if (pCredentialInfo && pCredentialInfo->clientCrt && pCredentialInfo->clientCrtSize) {
        bool go_nonopaque = true;

#if COMPONENT_AWSIOT_PKCS11PSA
        /* Go opaque first and non-opaque as fallback */
        go_nonopaque = false;
        bool go_opaque_ok = false;

        /* Un-initialize above client certificate/key for safe */
        ctx_->UninitClientCrtKey();

        do {
            /* Initialize crt context and keep it for TLS transport session */
            mbedtls_x509_crt_init(&ctx_->clientCrt);
            ctx_->clientCrtInited = true;
            int rc_mbedtls = mbedtls_x509_crt_parse(&ctx_->clientCrt,
                                                    (const unsigned char *) (pCredentialInfo->clientCrt),
                                                    pCredentialInfo->clientCrtSize);
            if (0 != rc_mbedtls) {
                LogError(("Error: mbedtls_x509_crt_parse failed: %d", rc_mbedtls));
                break;
            }

            if (0 == pCredentialInfo->clientKeyId) {
                LogError(("Error: Invalid PSA client key ID: 0"));
                break;
            }

            /* Acquire PSA client key handle for mbedtls_pk_setup_opaque */
            psa_status_t rc_psa = psa_open_key(pCredentialInfo->clientKeyId, &ctx_->clientKeyHandle);
            if (PSA_SUCCESS != rc_psa) {
                LogError(("Error: psa_open_key(%d) failed: %d", pCredentialInfo->clientKeyId, rc_psa));
                break;
            }
            if (0 == ctx_->clientKeyHandle) {
                LogError(("Error: PSA client key handle must be non-zero after psa_open_key(%d)", pCredentialInfo->clientKeyId));
                break;
            }

            /* Initialize pk context and keep it for TLS transport session */
            mbedtls_pk_init(&ctx_->clientkeyPKCtx);
            ctx_->clientkeyPKCtxInited = true;
            rc_mbedtls = mbedtls_pk_setup_opaque(&ctx_->clientkeyPKCtx, ctx_->clientKeyHandle);
            if (MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE == rc_mbedtls) {
                LogInfo(("Info: mbedtls hasn't supported this key type as opaque yet. Go non-opaque instead..."));
                go_nonopaque = true;
                break;
            } else if (0 != rc_mbedtls) {
                LogError(("Error: mbedtls_pk_setup_opaque(%d) failed: %d", ctx_->clientKeyHandle, rc_mbedtls));
                break;
            }

            /* TLSSocket hasn't supported opaque yet. Configure mbedtls SSL straight. */
            rc_mbedtls = mbedtls_ssl_conf_own_cert(ctx_->socket->get_ssl_config(),
                                                   &ctx_->clientCrt,
                                                   &ctx_->clientkeyPKCtx);
            if (0 != rc_mbedtls) {
                LogError(("Error: mbedtls_ssl_conf_own_cert failed: %d", rc_mbedtls));
                break;
            }

            go_opaque_ok = true;
        } while (0);

        /* Client certificate/key contexts are needed by mbedtls transport
         * session. Keep them. */
        if (!go_opaque_ok) {
            ctx_->UninitClientCrtKey();
        }
#endif

        /* Go non-opaque */
        if (go_nonopaque && pCredentialInfo->clientKey && pCredentialInfo->clientKeySize) {
            rc = ctx_->socket->set_client_cert_key(pCredentialInfo->clientCrt,
                                                   pCredentialInfo->clientCrtSize,
                                                   pCredentialInfo->clientKey,
                                                   pCredentialInfo->clientKeySize);
            if (rc != 0) {
                LogError(("Error: configure client certificate/private key into TLSSocket: %d", rc));
                goto cleanup;
            }
        }
    }

    /* Set ALPN extension */
    if (pCredentialInfo && pCredentialInfo->alpnProtos) {
        mbedtls_ssl_conf_alpn_protocols(ctx_->socket->get_ssl_config(), pCredentialInfo->alpnProtos);
    }

    /* Set 'host':'port' into 'sockaddr': */
    /* Translate 'host' to IP address */
    rc = net->gethostbyname(pServerInfo->hostname, &sockaddr);
    if (rc != 0) {
        LogError(("Network interface gethostbyname(%s) failed with %d", pServerInfo->hostname, rc));
        goto cleanup;
    }
    /* Set port into 'sockaddr' */
    sockaddr.set_port(pServerInfo->port);

    /* Open network socket */
    rc = ctx_->socket->open(net);
    if (rc != 0) {
        LogError(("TLS socket open failed with %d", rc));
        return -1;
    }

    /* Connect to remote peer */
    rc = ctx_->socket->connect(sockaddr);
    if (rc != 0) {
        LogError(("TLS socket connect failed with %d", rc));
        return -1;
    }

cleanup:

    if (rc != 0) {
        Mbed_Tls_Disconnect(pNetworkContext);
        return -1;
    } else {
        return 0;
    }
}

int32_t Mbed_Tls_Disconnect( NetworkContext_t * pNetworkContext )
{
    /* Validate parameters. */
    if (pNetworkContext == NULL) {
        LogError(("Parameter check failed: pNetworkContext is NULL."));
        return -1;
    }

    /* Cast 'pNetworkContext' to 'TlsNetworkContext_t *' for following net socket operations */
    auto *ctx_ = static_cast<TlsNetworkContext_t *>(static_cast<void *>(pNetworkContext));

    /* Validate socket */
    if (ctx_->socket == NULL) {
        LogError(("Parameter check failed: socket is NULL."));
        return -1;
    }

    /* Destruct socket */
    ctx_->socket->~TLSSocket();
    ctx_->socket = NULL;

#if COMPONENT_AWSIOT_PKCS11PSA
    /* Un-initialize client certificate/key */
    ctx_->UninitClientCrtKey();
#endif

    return 0;
}

int32_t Mbed_Tls_Recv( NetworkContext_t * pNetworkContext,
                       void * pBuffer,
                       size_t bytesToRecv )
{
   assert( pNetworkContext != NULL );
    assert( pBuffer != NULL );
    assert( bytesToRecv > 0 );

    /* Cast 'pNetworkContext' to 'TlsNetworkContext_t *' for following net socket operations */
    auto *ctx_ = static_cast<TlsNetworkContext_t *>(static_cast<void *>(pNetworkContext));

    /* Validate socket */
    if (ctx_->socket == NULL) {
        LogError(("Parameter check failed: socket is NULL."));
        return -1;
    }

    /* Configure timeout in ms. */
    ctx_->socket->set_timeout(ctx_->recvTimeoutMs);

    /* Invoke socket recv() and then cast return code */
    nsapi_size_or_error_t rc = ctx_->socket->recv(pBuffer, bytesToRecv);
    if (rc > 0) {
        return rc;
    } else if (rc == 0) {
        /* Peer has closed the connection. Treat as an error. */
        LogError(("No more buffered receive data and peer has closed the connection."));
        return -1;
    } else if (rc == NSAPI_ERROR_WOULD_BLOCK) {
        if (ctx_->recvTimeoutMs) {
            // If the error code represents a timeout, then the return
            // code should be translated to zero so that the caller
            // can retry the read operation.
            return 0;
        } else {
            return 0;
        }
    } else {
        LogError(("Socket recv(%d), timeout(%d) failed with %d", bytesToRecv, ctx_->sendTimeoutMs, rc));
        return -1;
    }
}

int32_t Mbed_Tls_Send( NetworkContext_t * pNetworkContext,
                       const void * pBuffer,
                       size_t bytesToSend )
{
    assert( pNetworkContext != NULL );
    assert( pBuffer != NULL );
    assert( bytesToSend > 0 );

    /* Cast 'pNetworkContext' to 'TlsNetworkContext_t *' for following net socket operations */
    auto *ctx_ = static_cast<TlsNetworkContext_t *>(static_cast<void *>(pNetworkContext));

    /* Validate socket */
    if (ctx_->socket == NULL) {
        LogError(("Parameter check failed: socket is NULL."));
        return -1;
    }

    /* Configure timeout in ms. */
    ctx_->socket->set_timeout(ctx_->sendTimeoutMs);

    /* Invoke socket send() and then cast return code */
    nsapi_size_or_error_t rc = ctx_->socket->send(pBuffer, bytesToSend);
    if (rc > 0) {
        return rc;
    } else if (rc == 0) {
        /* FIXME: Unclear definition with send zero in Mbed OS Socket. Treat as error */
        LogError(("Unclear definition with send zero in Mbed OS Socket. Treat as error."));
        return -1;
    } else if (rc == NSAPI_ERROR_WOULD_BLOCK) {
        if (ctx_->sendTimeoutMs) {
            // If the error code represents a timeout, then the return
            // code should be translated to zero so that the caller
            // can retry the write operation.
            return 0;
        } else {
            return 0;
        }
    } else {
        LogError(("Socket send(%d), timeout(%d) failed with %d", bytesToSend, ctx_->sendTimeoutMs, rc));
        return -1;
    }
}
