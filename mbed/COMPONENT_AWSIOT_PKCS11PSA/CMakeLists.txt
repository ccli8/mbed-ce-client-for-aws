# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

target_include_directories(mbed-ce-client-for-aws
    PUBLIC
        .
        corePKCS11
        FreeRTOS_mbed
)

target_sources(mbed-ce-client-for-aws
    PRIVATE
        corePKCS11/core_pkcs11.c
        corePKCS11/core_pki_utils.c
        FreeRTOS_mbed/FreeRTOS_mbed.cpp
        mbedtls_utils/mbedtls_utils.c
)
