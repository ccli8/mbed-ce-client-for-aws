# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

target_include_directories(mbed-ce-client-for-aws
    PUBLIC
        .
        pkcs11
)

target_sources(mbed-ce-client-for-aws
    PRIVATE
        iot_pkcs11_psa.c
        iot_pkcs11_psa_input_format.c
        iot_pkcs11_psa_object_management.c
)
