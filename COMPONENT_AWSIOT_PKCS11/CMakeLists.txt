# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

target_include_directories(mbed-ce-client-for-aws
    PUBLIC
        .
        corePKCS11/source/include
        corePKCS11/source/dependency/3rdparty/mbedtls_utils
        pkcs11   
)

target_sources(mbed-ce-client-for-aws
    PRIVATE
        corePKCS11/source/core_pkcs11.c
        corePKCS11/source/core_pki_utils.c
        corePKCS11/source/dependency/3rdparty/mbedtls_utils/mbedtls_utils.c
        corePKCS11/source/portable/mbedtls/core_pkcs11_mbedtls.c
)
