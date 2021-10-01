/*
 * Copyright (C) 2019 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 * Copyright (c) 2019-2020 Arm Limited. All Rights Reserved.
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
 */

#include "mbed.h"
#include "FreeRTOS_mbed.h"

SemaphoreHandle_t xSemaphoreCreateMutex( void )
{
    Mutex *mutex = new Mutex;

    return mutex;
}

BaseType_t xSemaphoreTake( SemaphoreHandle_t xSemaphore,
                           TickType_t xTicksToWait )
{
    Mutex *mutex = static_cast<Mutex *>(xSemaphore);

    return mutex->trylock_for(std::chrono::milliseconds(xTicksToWait)) ? pdTRUE : pdFALSE;
}

BaseType_t xSemaphoreGive( SemaphoreHandle_t xSemaphore )
{
    Mutex *mutex = static_cast<Mutex *>(xSemaphore);

    mutex->unlock();

    return pdTRUE;
}

void vSemaphoreDelete( SemaphoreHandle_t xSemaphore )
{
    Mutex *mutex = static_cast<Mutex *>(xSemaphore);

    delete mutex;
}
