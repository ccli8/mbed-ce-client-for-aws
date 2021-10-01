/*
 *  Threading abstraction layer
 *
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

#include "mbed.h"
#include "mbed_trace.h"
#include "mbedtls/threading.h"

#define TRACE_GROUP     "MbedTLS_Threading"

/* Guarantee estimated memory for rtos::Mutex is enough */
MBED_STATIC_ASSERT(THREADING_MUTEX_BLOCK_SIZE >= sizeof(rtos::Mutex),
                   "Insufficient memory allocation for rtos::Mutex");

struct threading_alt_ctx
{
    threading_alt_ctx()
    {
        mbedtls_threading_set_alt(threading_mutex_init_mbed,
                                  threading_mutex_free_mbed,
                                  threading_mutex_lock_mbed,
                                  threading_mutex_unlock_mbed);
    }
    
    ~threading_alt_ctx()
    {
        mbedtls_threading_free_alt();
    }
};

/* Setup threading alt functions */
threading_alt_ctx threading_alt_ctx_;

void threading_mutex_init_mbed(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == nullptr) {
        return;
    }

    mutex->mutex = new (mutex->mutex_block) rtos::Mutex;
}

void threading_mutex_free_mbed(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == nullptr || mutex->mutex == nullptr) {
        return;
    }

    ((rtos::Mutex *) mutex->mutex)->~Mutex();
    mutex->mutex = nullptr;
}

int threading_mutex_lock_mbed(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == nullptr || mutex->mutex == nullptr) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }

    ((rtos::Mutex *) mutex->mutex)->lock();

    return 0;
}

int threading_mutex_unlock_mbed(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == nullptr || mutex->mutex == nullptr) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }

    ((rtos::Mutex *) mutex->mutex)->unlock();

    return 0;
}
