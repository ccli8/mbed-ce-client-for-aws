# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

target_include_directories(mbed-client-for-aws
    INTERFACE
        .
)

# Meet unclear trouble with genex inside target_sources. Change to if-else as workaround.
if("AWSIOT_PKCS11_KVSTORE" IN_LIST MBED_TARGET_LABELS)
    target_sources(mbed-client-for-aws
        INTERFACE
            COMPONENT_AWSIOT_PKCS11_KVSTORE/core_pkcs11_pal.cpp
    )
endif()
