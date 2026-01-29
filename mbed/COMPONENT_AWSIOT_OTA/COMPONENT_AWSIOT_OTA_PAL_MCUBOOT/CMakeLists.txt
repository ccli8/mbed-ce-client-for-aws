# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

target_include_directories(mbed-ce-client-for-aws
    PUBLIC
        .
        mcuboot/boot/bootutil/include
        mcuboot/boot/bootutil/src
        mcuboot/boot/mbed/include
        mcuboot/boot/mbed/include
)

target_sources(mbed-ce-client-for-aws
    PRIVATE
        flash_map_backend.cpp
        mcuboot/boot/bootutil/src/bootutil_public.c
        ota_pal_mcuboot.cpp
        secondary_bd.cpp
)
