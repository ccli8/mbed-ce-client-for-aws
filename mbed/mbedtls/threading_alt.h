/**
 * \file threading_alt.h
 *
 * \brief Threading abstraction layer
 */
/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef THREADING_ALT_H
#define THREADING_ALT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* This header file cannot include C++ stuff to be included by mbedtls without error.
 * To meet this, rtos::Mutex cannot be used for memory requirement calculation. Instead,
 * estimate this memory requirement to accommodate rtos::Mutex. This must be checked in
 * threading_alt.cpp which can include rtos::Mutex. */
#define THREADING_MUTEX_BLOCK_SIZE          64

/**
 * \brief   struct for MBEDTLS_THREADING_ALT
 */
struct mbedtls_threading_mutex
{
    uint64_t        mutex_block[(THREADING_MUTEX_BLOCK_SIZE + 7) / 8];
    void *          mutex;
};

typedef struct mbedtls_threading_mutex  mbedtls_threading_mutex_t;

/**
 * \brief   Initialize mbedtls_threading_mutex_t statically
 */
#define MUTEX_INIT  = { .mutex = NULL }

/**
 * \brief   functions for MBEDTLS_THREADING_ALT
 *
 * All these functions are expected to work or the result will be undefined.
 */
void threading_mutex_init_mbed(mbedtls_threading_mutex_t *mutex);
void threading_mutex_free_mbed(mbedtls_threading_mutex_t *mutex);
int threading_mutex_lock_mbed(mbedtls_threading_mutex_t *mutex);
int threading_mutex_unlock_mbed(mbedtls_threading_mutex_t *mutex);

#ifdef __cplusplus
}
#endif

#endif /* ifndef THREADING_ALT_H */
