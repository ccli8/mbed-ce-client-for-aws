/*
 * corePKCS11 V3.0.0
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

#ifndef _CORE_PKI_UTILS_H_
#define _CORE_PKI_UTILS_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file core_pki_utils.h
 * @brief Helper functions for PKCS #11
 */

/**
 * @brief Converts an ECDSA signature from the format provided by mbedTLS
 * to the format expected by PKCS #11.
 *
 * mbedTLS provides signatures in DER encoded, zero-padded format.
 *
 * @param[out] pxSignaturePKCS            Pointer to a buffer
 *                                        where PKCS #11 formatted signature
 *                                        will be placed. Caller must
 *                                        allocate at least twice {R, S} component
 *                                        bytes of memory.
 * Qparam[in,out] pxPKCSSignatureLength   PKCS signature buffer size in bytes on input,
 *                                        actual size in bytes on output
 * @param[in] pxMbedSignature             Pointer to DER encoded ECDSA
 *                                        signature.
 * @param[in] xMbedSignatureLength        Buffer size of pxMbedSignature
 *
 * \return 0 on success, -1 on failure.
 */
/* @[declare_pkcs11_utils_pkimbedtlssignaturetopkcs11signature] */
int8_t PKI_mbedTLSSignatureToPkcs11Signature( uint8_t * pxPKCSSignature,
                                              size_t *pxPKCSSignatureLength,
                                              const uint8_t * pxMbedSignature,
                                              size_t xMbedSignatureLength );
/* @[declare_pkcs11_utils_pkimbedtlssignaturetopkcs11signature] */



/**
 * @brief Converts and ECDSA signature from the format provided by PKCS #11
 * to an ASN.1 formatted signature.
 *
 * @param[in,out] pucSig     This pointer serves dual purpose.
 *                           It should both contain the PKCS #11
 *                           style signature on input, and will be modified
 *                           to hold the ASN.1 formatted signature (max length
 *                           xSigMaxLen).  It is the responsibility of the caller
 *                           to guarantee that this pointer is large enough to
 *                           hold the (longer) formatted signature.
 *@param[in,out] pxSigLen    Pointer to the length of the PKCS #11 signature on input,
 *                           ASN.1 formatted signature on output.
 *@param[in]     xSigMaxLen  Maximum buffer size of pucSig
 *
 * \return 0 if successful, -1 on failure.
 *
 */
/* @[declare_pkcs11_utils_pkipkcs11signaturetombedtlssignature] */
int8_t PKI_pkcs11SignatureTombedTLSSignature( uint8_t * pucSig,
                                              size_t * pxSigLen,
                                              size_t xSigMaxLen );
/* @[declare_pkcs11_utils_pkipkcs11signaturetombedtlssignature] */

#ifdef __cplusplus
}
#endif

#endif /* ifndef _CORE_PKI_UTILS_H_ */
