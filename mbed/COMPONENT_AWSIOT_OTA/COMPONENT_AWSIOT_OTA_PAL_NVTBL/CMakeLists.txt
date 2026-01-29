# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

target_include_directories(mbed-ce-client-for-aws
    PUBLIC
        .
)

target_sources(mbed-ce-client-for-aws
    PRIVATE
        ota_pal_mbed.cpp
)
