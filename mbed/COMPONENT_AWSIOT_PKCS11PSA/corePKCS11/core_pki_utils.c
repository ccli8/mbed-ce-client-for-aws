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

/**
 * @file core_pki_utils.c
 * @brief Helper functions for PKCS #11
 */
#include "core_pki_utils.h"

/* CRT includes. */
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* MbedTLS includes. */
#include "mbedtls/pk_internal.h"
//#include "mbedtls/ecp.h"
//#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/asn1.h"
#include "mbedtls/error.h"

/**
 * @ingroup pkcs11_macros
 * @brief Failure value for PKI utils functions.
 */
#define FAILURE    ( -1 )

/*-----------------------------------------------------------*/

/* The functions below are moved from mbedtls pk_wrap.c to help transcode,
 * for ECC, between mbedtls signature and pkcs11/psa signature. */

/*
 * An ASN.1 encoded signature is a sequence of two ASN.1 integers. Parse one of
 * those integers and convert it to the fixed-length encoding expected by PSA.
 */
static int extract_ecdsa_sig_int( unsigned char **from, const unsigned char *end,
                                  unsigned char *to, size_t to_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t unpadded_len, padding_len;

    if( ( ret = mbedtls_asn1_get_tag( from, end, &unpadded_len,
                                      MBEDTLS_ASN1_INTEGER ) ) != 0 )
    {
        return( ret );
    }

    while( unpadded_len > 0 && **from == 0x00 )
    {
        ( *from )++;
        unpadded_len--;
    }

    if( unpadded_len > to_len || unpadded_len == 0 )
        return( MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    padding_len = to_len - unpadded_len;
    memset( to, 0x00, padding_len );
    memcpy( to + padding_len, *from, unpadded_len );
    ( *from ) += unpadded_len;

    return( 0 );
}

/*
 * Convert a signature from an ASN.1 sequence of two integers
 * to a raw {r,s} buffer. Note: the provided sig buffer must be at least
 * twice as big as int_size.
 */
static int extract_ecdsa_sig( unsigned char **p, const unsigned char *end,
                              unsigned char *sig, size_t int_size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t tmp_size;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &tmp_size,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( ret );

    /* Extract r */
    if( ( ret = extract_ecdsa_sig_int( p, end, sig, int_size ) ) != 0 )
        return( ret );
    /* Extract s */
    if( ( ret = extract_ecdsa_sig_int( p, end, sig + int_size, int_size ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Simultaneously convert and move raw MPI from the beginning of a buffer
 * to an ASN.1 MPI at the end of the buffer.
 * See also mbedtls_asn1_write_mpi().
 *
 * p: pointer to the end of the output buffer
 * start: start of the output buffer, and also of the mpi to write at the end
 * n_len: length of the mpi to read from start
 */
static int asn1_write_mpibuf( unsigned char **p, unsigned char *start,
                              size_t n_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if( (size_t)( *p - start ) < n_len )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    len = n_len;
    *p -= len;
    memmove( *p, start, len );

    /* ASN.1 DER encoding requires minimal length, so skip leading 0s.
     * Neither r nor s should be 0, but as a failsafe measure, still detect
     * that rather than overflowing the buffer in case of a PSA error. */
    while( len > 0 && **p == 0x00 )
    {
        ++(*p);
        --len;
    }

    /* this is only reached if the signature was invalid */
    if( len == 0 )
        return( MBEDTLS_ERR_PK_HW_ACCEL_FAILED );

    /* if the msb is 1, ASN.1 requires that we prepend a 0.
     * Neither r nor s can be 0, so we can assume len > 0 at all times. */
    if( **p & 0x80 )
    {
        if( *p - start < 1 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = 0x00;
        len += 1;
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start,
                                                MBEDTLS_ASN1_INTEGER ) );

    return( (int) len );
}

/* Transcode signature from PSA format to ASN.1 sequence.
 * See ecdsa_signature_to_asn1 in ecdsa.c, but with byte buffers instead of
 * MPIs, and in-place.
 *
 * [in/out] sig: the signature pre- and post-transcoding
 * [in/out] sig_len: signature length pre- and post-transcoding
 * [int] buf_len: the available size the in/out buffer
 */
static int pk_ecdsa_sig_asn1_from_psa( unsigned char *sig, size_t *sig_len,
                                       size_t buf_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    const size_t rs_len = *sig_len / 2;
    unsigned char *p = sig + buf_len;

    MBEDTLS_ASN1_CHK_ADD( len, asn1_write_mpibuf( &p, sig + rs_len, rs_len ) );
    MBEDTLS_ASN1_CHK_ADD( len, asn1_write_mpibuf( &p, sig, rs_len ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &p, sig, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &p, sig,
                          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    memmove( sig, p, len );
    *sig_len = len;

    return( 0 );
}

/*-----------------------------------------------------------*/

/* Convert the EC signature from DER encoded to PKCS #11 format. */
/* @[declare pkcs11_utils_pkipkcs11signaturetombedtlssignature] */
int8_t PKI_mbedTLSSignatureToPkcs11Signature( uint8_t * pxPKCSSignature,
                                              size_t *pxPKCSSignatureLength,
                                              const uint8_t * pxMbedSignature,
                                              size_t xMbedSignatureLength )
{
    int8_t xReturn = 0;
    const uint8_t * pxNextLength = NULL;
    size_t xRSComponentLength = 0;

    if( ( pxPKCSSignature == NULL ) ||
        ( pxPKCSSignatureLength == NULL ) ||
        ( pxMbedSignature == NULL ) )
    {
        xReturn = FAILURE;
    }

    /* Abstracting from mbedtls ecdsa.c, fetch {r, s} component length. */
    if (xReturn == 0) {
        mbedtls_mpi r, s;
        mbedtls_mpi_init( &r );
        mbedtls_mpi_init( &s );
    
        unsigned char *p = (unsigned char *) pxMbedSignature;
        const unsigned char *end = pxMbedSignature + xMbedSignatureLength;
        size_t len;
        size_t r_bitlen;
        size_t s_bitlen;

        if ( 0 != mbedtls_asn1_get_tag( &p, end, &len,
                                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) {
            xReturn = FAILURE;
            goto cleanup_rs;
        }

        if ( ( p + len ) != end) {
            xReturn = FAILURE;
            goto cleanup_rs;
        }

        if ( 0 != mbedtls_asn1_get_mpi( &p, end, &r ) ) {
            xReturn = FAILURE;
            goto cleanup_rs;
        }
        if ( 0 != mbedtls_asn1_get_mpi( &p, end, &s ) ) {
            xReturn = FAILURE;
            goto cleanup_rs;
        }

        r_bitlen = mbedtls_mpi_bitlen( &r );
        s_bitlen = mbedtls_mpi_bitlen( &s );
        xRSComponentLength = ( r_bitlen + 7 ) / 8;

cleanup_rs:
        mbedtls_mpi_free( &r );
        mbedtls_mpi_free( &s );
    }

    if( xReturn == 0 ) {
        if ((xRSComponentLength * 2) > *pxPKCSSignatureLength) {
            xReturn = FAILURE;
        }
    }

    if( xReturn == 0 )
    {
        int rc_mbedtls = 0;
        unsigned char *p = (unsigned char *) pxMbedSignature;
        rc_mbedtls = extract_ecdsa_sig(&p,
                                       (const unsigned char *) (pxMbedSignature + xMbedSignatureLength),
                                       (unsigned char *) pxPKCSSignature,
                                       xRSComponentLength);
        if (0 != rc_mbedtls) {
            printf("extract_ecdsa_sig failed: %d\r\n", rc_mbedtls);
            xReturn = FAILURE;
        }
        
        *pxPKCSSignatureLength = xRSComponentLength * 2;
    }

    return xReturn;
}
/* @[declare pkcs11_utils_pkipkcs11signaturetombedtlssignature] */
/*-----------------------------------------------------------*/


/* Convert an EC signature from PKCS #11 format to DER encoded. */
/* @[declare pkcs11_utils_pkimbedtlssignaturetopkcs11signature] */
int8_t PKI_pkcs11SignatureTombedTLSSignature( uint8_t * pucSig,
                                              size_t * pxSigLen,
                                              size_t xSigMaxLen )
{
    int8_t xReturn = 0;

    if( ( pucSig == NULL ) || ( pxSigLen == NULL ) )
    {
        xReturn = FAILURE;
    }

    if( xReturn == 0 )
    {
        int rc_mbedtls = 0;
        rc_mbedtls = pk_ecdsa_sig_asn1_from_psa((unsigned char *) pucSig,
                                                pxSigLen,
                                                xSigMaxLen);
        if (0 != rc_mbedtls) {
            printf("extract_ecdsa_sig failed: %d\r\n", rc_mbedtls);
            xReturn = FAILURE;
        }
    }

    return xReturn;
}
/* @[declare pkcs11_utils_pkimbedtlssignaturetopkcs11signature] */
