# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(mbed-client-for-aws INTERFACE)


target_include_directories(mbed-client-for-aws
    INTERFACE
        .
        backoffAlgorithm/source/include
        CMock/src
        COMPONENT_AWSIOT_DEVICEDEFENDER/device-defender-for-aws-iot-embedded-sdk/source/include
        COMPONENT_AWSIOT_DEVICESHADOW/device-shadow-for-aws-iot-embedded-sdk/source/include
        COMPONENT_AWSIOT_FLEETPROVISIONING/Fleet-Provisioning-for-AWS-IoT-embedded-sdk/source/include
        COMPONENT_AWSIOT_HTTP/coreHTTP/source/include
        COMPONENT_AWSIOT_HTTP/coreHTTP/source/interface
        COMPONENT_AWSIOT_HTTP/http-parser
        COMPONENT_AWSIOT_JOBS/jobs-for-aws-iot-embedded-sdk/source/include
        COMPONENT_AWSIOT_JSON/coreJSON/source/include
        COMPONENT_AWSIOT_MQTT/coreMQTT/source/include
        COMPONENT_AWSIOT_MQTT/coreMQTT/source/interface
        COMPONENT_AWSIOT_OTA/ota-for-aws-iot-embedded-sdk/source/include
        COMPONENT_AWSIOT_PKCS11/corePKCS11/source/include
        COMPONENT_AWSIOT_PKCS11/corePKCS11/source/dependency/3rdparty/mbedtls_utils
        COMPONENT_AWSIOT_PKCS11/pkcs11
        COMPONENT_AWSIOT_SIGV4/SigV4-for-AWS-IoT-embedded-sdk/source/include
        mbed/COMPONENT_AWSIOT_MQTT
        mbed/COMPONENT_AWSIOT_OTA
        mbed/COMPONENT_AWSIOT_OTA/COMPONENT_AWSIOT_OTA_PAL_NVTBL
        mbed/COMPONENT_AWSIOT_OTA/crypto
        mbed/COMPONENT_AWSIOT_OTA/os
        mbed/COMPONENT_AWSIOT_PKCS11
        mbed/mbedtls
        mbed/transport/include 
        tinycbor/src
        logging-stack
        aws-iot-device-sdk-embedded-C/platform/include
)

target_sources(mbed-client-for-aws
    INTERFACE
        COMPONENT_AWSIOT_JOBS/jobs-for-aws-iot-embedded-sdk/source/jobs.c
        COMPONENT_AWSIOT_JSON/coreJSON/source/core_json.c
        COMPONENT_AWSIOT_MQTT/coreMQTT/source/core_mqtt.c
        COMPONENT_AWSIOT_MQTT/coreMQTT/source/core_mqtt_serializer.c
        COMPONENT_AWSIOT_MQTT/coreMQTT/source/core_mqtt_state.c
        COMPONENT_AWSIOT_OTA/ota-for-aws-iot-embedded-sdk/source/ota.c
        COMPONENT_AWSIOT_OTA/ota-for-aws-iot-embedded-sdk/source/ota_base64.c
        COMPONENT_AWSIOT_OTA/ota-for-aws-iot-embedded-sdk/source/ota_cbor.c
        COMPONENT_AWSIOT_OTA/ota-for-aws-iot-embedded-sdk/source/ota_http.c
        COMPONENT_AWSIOT_OTA/ota-for-aws-iot-embedded-sdk/source/ota_interface.c
        COMPONENT_AWSIOT_OTA/ota-for-aws-iot-embedded-sdk/source/ota_mqtt.c
        COMPONENT_AWSIOT_PKCS11/corePKCS11/source/core_pkcs11.c
        COMPONENT_AWSIOT_PKCS11/corePKCS11/source/core_pki_utils.c
        COMPONENT_AWSIOT_PKCS11/corePKCS11/source/dependency/3rdparty/mbedtls_utils/mbedtls_utils.c
        COMPONENT_AWSIOT_PKCS11/corePKCS11/source/portable/mbedtls/core_pkcs11_mbedtls.c
        backoffAlgorithm/source/backoff_algorithm.c
        mbed/COMPONENT_AWSIOT_OTA/COMPONENT_AWSIOT_OTA_PAL_NVTBL/ota_pal_mbed.cpp
        mbed/COMPONENT_AWSIOT_OTA/crypto/iot_crypto.cpp
        mbed/COMPONENT_AWSIOT_OTA/os/ota_os_mbed.cpp
        mbed/COMPONENT_AWSIOT_PKCS11/COMPONENT_AWSIOT_PKCS11_KVSTORE/core_pkcs11_pal.cpp
        mbed/mbedtls/threading_alt.cpp
        mbed/clock/src/clock_mbed.cpp
        mbed/transport/src/transport_mbed_tcp.cpp
        mbed/transport/src/transport_mbed_tls.cpp
        tinycbor/src/cborencoder.c
        tinycbor/src/cborencoder_close_container_checked.c
        tinycbor/src/cborerrorstrings.c
        tinycbor/src/cborparser.c
        tinycbor/src/cborparser_dup_string.c
        tinycbor/src/cborpretty.c
        tinycbor/src/cborvalidation.c
)

