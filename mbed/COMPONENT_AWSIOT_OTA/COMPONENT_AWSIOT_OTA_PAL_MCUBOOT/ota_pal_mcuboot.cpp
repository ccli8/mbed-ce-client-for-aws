/*
 * OTA PAL for Nuvoton NuMaker
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/* OTA PAL implementation for NuMaker Mbed platform, using MCUboot with image revert enabled. */

#if defined(__ICCARM__)
/* Suppress warning message Pe111: statement is unreachable for otaPal_ResetDevice() */
#pragma diag_suppress=Pe111
#endif

#if defined(__ICCARM__)
/* IAR C++ doesn't support C11 _Static_assert. Translate to C++11 static_assert. */
#ifdef __cplusplus
#define _Static_assert  static_assert
#endif
#endif

/* Standard includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/* Mbed includes */
#include "mbed.h"
#include "mbed_trace.h"
#include "kvstore_global_api.h"

/* MCUboot includes */
#include "bootutil/bootutil.h"
#include "bootutil/image.h"
#include "flash_map_backend/secondary_bd.h"
#include "sysflash/sysflash.h"

/* OTA PAL includes */
#include "ota_pal_mcuboot.h"
#include "aws_credentials_provision_kvstore.h"

/* PKCS11 includes */
#include "core_pkcs11_config.h"
#include "core_pkcs11.h"
#include "iot_crypto.h"

/* DO NOT enable code verification by PKCS11
 *
 * AWS itself is inconsistent on which is provisioned for code verification,
 * public key or certificate, identified by pkcs11configLABEL_CODE_VERIFICATION_KEY.
 * 
 * According to code snippet below, this PKCS11 label must identify public key, not
 * certificate:
 * https://github.com/FreeRTOS/corePKCS11/blob/bae1709685b6091fdcfa80843f9d269602c9defc/source/portable/mbedtls/core_pkcs11_mbedtls.c#L4534
 *
 * But our code like provision, CRYPTO_SignatureVerificationFinal(), and
 * COMPONENT_AWSIOT_OTA_PAL_NVTBL has done assuming this PKCS11 label identifying
 * certificate. Before one good solution comes out to address backwards-incompatible
 * issue, we cannot enable code verification by PKCS11.
 */
#define ENABLE_CODE_VERIFY_BY_PKCS11                0

/* Default read block size for calculating image digest from secondary bd */
#define FWU_READ_BLOCK_DEFSIZE                      1024

/* KVStore key to in-storage struct OTA_NonVolatileImageUpgradeState_t */
#define OTA_IMAGE_UPDATE_STATE_KEY                  "ota_image_update_state"

/* Stringize */
#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

/* Convert to KVStore default fully-qualified key path */
#define KV_DEF_FQ_KEY(KEY)                      \
    "/" STR(MBED_CONF_STORAGE_DEFAULT_KV) "/" KEY
    
/* Specify the OTA signature algorithm we support on this platform. */
const char OTA_JsonFileSignatureKey[ OTA_FILE_SIG_KEY_STR_MAX_LENGTH ] = "sig-sha256-ecdsa";

typedef struct
{
    const OtaFileContext_t *    pxOTAFileCtx;       // OTA Agent file context

    /* MCUboot firmware update context: Active */
    struct fwu_active_s {
        struct image_header     image_header;
    } fwu_active;

    /* MCUboot firmware update context: Stage */
    struct fwu_stage_s {
        struct image_header     image_header;               // Cached image header on the fly
        BlockDevice *           secondary_bd;               // Secondary BlockDevice
        bool                    secondary_bd_inited;
        void *                  secondary_bd_progunit;      // Program unit buffer to cover unaligned last data block
        size_t                  secondary_bd_progunit_size;
        void *                  secondary_bd_readblock;     // Read block buffer which must align on read unit boundary
        size_t                  secondary_bd_readblock_size;
    } fwu_stage;
} OTA_OperationDescriptor_t;

/* NOTE that this implementation supports only one OTA at a time since it uses a single static instance. */
static OTA_OperationDescriptor_t xCurOTAOpDesc;     // OTA operation in progress

/*-----------------------------------------------------------*/

/* Validate OTA Agent/OTA PAL are linked */
static inline bool prvContextValidate( OtaFileContext_t * C )
{
    return ((NULL != C) &&
            (NULL != C->pFile) &&
            ((uintptr_t) C == (uintptr_t) ((OTA_OperationDescriptor_t *) C->pFile)->pxOTAFileCtx));
}

/* Unlink OTA Agent/OTA PAL */
static inline void prvContextUnlink( OtaFileContext_t * C )
{
    if (NULL != C && NULL != C->pFile) {
        ((OTA_OperationDescriptor_t *) C->pFile)->pxOTAFileCtx = NULL;
        C->pFile = NULL;
    }
}

/*-----------------------------------------------------------*/

static bool otaUtil_sigVerCrt(uint8_t **p_cred, size_t *p_cred_size);
static bool otaUtil_VerSig(OtaFileContext_t * const C);

/*-----------------------------------------------------------*/

/* In-storage struct for holding OTA PAL/MCUboot FWU states which need to be non-volatile to cross reset cycle */
typedef struct {
    /* MCUboot version of stage, non-secure image */
    bool                stageVersion_valid;
    struct image_version    stageVersion;

    /* OTA PAL image state */
    bool                imageState_valid;
    OtaPalImageState_t  imageState;

    /* Flag for install rebooted */
    bool                installRebooted_valid;
    bool                installRebooted;
} OTA_NonVolatileImageUpgradeState_t;

/* Routines to operate in-storage OTA_NonVolatileImageUpgradeState_t struct */
static bool nvImgUpgSt_reset(void);
static bool nvImgUpgSt_setStageVersion(struct image_version *stageVersion);
static bool nvImgUpgSt_setImageState(OtaPalImageState_t imageState);
static bool nvImgUpgSt_setInstallRebooted(bool installRebooted);
static bool nvImgUpgSt_installed(bool *confirmed);
static bool nvImgUpgSt_imageState(OtaPalImageState_t *imageState);
static bool nvImgUpgSt_installRebooted(bool *installRebooted);
static bool nvImgUpgSt_setAll(const OTA_NonVolatileImageUpgradeState_t *imageUpgradeState);
static bool nvImgUpgSt_getAll(OTA_NonVolatileImageUpgradeState_t *imageUpgradeState);

/* Helper class for updating OTA_NonVolatileImageUpgradeState_t immediately after reboot */
class Update_NVImgUpgSt_PostReboot
{
public:
    Update_NVImgUpgSt_PostReboot();
};

Update_NVImgUpgSt_PostReboot::Update_NVImgUpgSt_PostReboot()
{
    /* Indicate install rebooted */
    bool installRebooted = false;
    if (nvImgUpgSt_installRebooted(&installRebooted) &&
        !installRebooted) {
        nvImgUpgSt_setInstallRebooted(true);
    }
}

/* Confirm image revert when MCUboot upgrade strategy is SWAP through C++ global object constructor */
Update_NVImgUpgSt_PostReboot update_nvImgUpgSt_postReboot;

/*-----------------------------------------------------------*/

/* Attempt to create a new receive file for the file chunks as they come in. */

OtaPalStatus_t otaPal_CreateFileForRx( OtaFileContext_t * const C )
{
    OtaPalStatus_t result = OTA_PAL_COMBINE_ERR( OtaPalSuccess, 0 );

    /* Unnecessary to check C for NULL because OTA Agent has guaranteed */

    LogInfo(("otaPal_CreateFileForRx()..."));

    /* Clean up for fresh OTA session as possible */
    otaPal_Abort(C);

    /* Support only one instance */
    OTA_OperationDescriptor_t *pxCurOTADesc = &xCurOTAOpDesc;

    /* Clean, zero-initialized struct */
    memset(pxCurOTADesc, 0x00, sizeof(OTA_OperationDescriptor_t));

    /* Link OTA Agent/OTA PAL */
    C->pFile = (uint8_t *) pxCurOTADesc;
    pxCurOTADesc->pxOTAFileCtx = C;

    /* Ignore update file pathname */
    if (C->pFilePath && C->filePathMaxSize) {
        LogWarn(("Ignore update file pathname %.*s",
                 C->filePathMaxSize,
                 C->pFilePath));
    }

    /* Reset non-volatile image state */
    if (!nvImgUpgSt_reset()) {
        LogError(("nvImgUpgSt_reset() failed"));
        result = OTA_PAL_COMBINE_ERR( OtaPalRxFileCreateFailed, -1 );
        goto cleanup;
    }

    /* Image state 'Invalid' for FWU start */
    if (!nvImgUpgSt_setImageState(OtaPalImageStateInvalid)) {
        LogError(("otaPal_CreateFileForRx() failed: nvImgUpgSt_setImageState(%d) failed", OtaPalImageStateInvalid));
        result = OTA_PAL_COMBINE_ERR( OtaPalRxFileCreateFailed, -1 );
        goto cleanup;
    }

    /* Prepare secondary bd */
    {
        /* Get secondary bd */
        pxCurOTADesc->fwu_stage.secondary_bd = get_secondary_bd();
        if (pxCurOTADesc->fwu_stage.secondary_bd == NULL) {
            LogError(("get_secondary_bd() failed"));
            result = OTA_PAL_COMBINE_ERR( OtaPalRxFileCreateFailed, -1 );
            goto cleanup;
        }

        /* Initialize secondary bd */
        int rc = pxCurOTADesc->fwu_stage.secondary_bd->init();
        if (rc != 0) {
            LogError(("Secondary BlockDevice init() failed: -%08x", -rc));
            result = OTA_PAL_COMBINE_ERR( OtaPalRxFileCreateFailed, -1 );
            goto cleanup;
        }
        pxCurOTADesc->fwu_stage.secondary_bd_inited = true;

        pxCurOTADesc->fwu_stage.secondary_bd_progunit_size = pxCurOTADesc->fwu_stage.secondary_bd->get_program_size();
        pxCurOTADesc->fwu_stage.secondary_bd_progunit = malloc(pxCurOTADesc->fwu_stage.secondary_bd_progunit_size);

        size_t read_size = pxCurOTADesc->fwu_stage.secondary_bd->get_read_size();
        pxCurOTADesc->fwu_stage.secondary_bd_readblock_size = FWU_READ_BLOCK_DEFSIZE;
        if (FWU_READ_BLOCK_DEFSIZE < read_size) {
            pxCurOTADesc->fwu_stage.secondary_bd_readblock_size = read_size;
        }
        pxCurOTADesc->fwu_stage.secondary_bd_readblock = malloc(pxCurOTADesc->fwu_stage.secondary_bd_readblock_size);

        size_t second_bd_size = pxCurOTADesc->fwu_stage.secondary_bd->size();
        LogInfo(("Secondary BlockDevice size: %d (bytes)", second_bd_size));

        /* Erase secondary bd */
        rc = pxCurOTADesc->fwu_stage.secondary_bd->erase(0, second_bd_size);
        if (rc != 0) {
            LogError(("Secondary BlockDevice erase() failed: -%08x", -rc));
            result = OTA_PAL_COMBINE_ERR( OtaPalRxFileCreateFailed, -1 );
            goto cleanup;
        }
    }

    /* Get active image's version */
    {
        const struct image_header *header = (const struct image_header *) MCUBOOT_PRIMARY_SLOT_START_ADDR;
        if (header->ih_magic != IMAGE_MAGIC) {
            LogError(("Active image header error: Magic: EXP 0x%08x ACT 0x%08x", IMAGE_MAGIC, header->ih_magic));
            result = OTA_PAL_COMBINE_ERR( OtaPalRxFileCreateFailed, -1 );
            goto cleanup;
        }
        memcpy(&(pxCurOTADesc->fwu_active.image_header),
               header,
               sizeof(struct image_header));

        struct image_version *active_image_version = &(pxCurOTADesc->fwu_active.image_header.ih_ver);
        LogInfo(("Active image version: %d.%d.%d+%d",
                 active_image_version->iv_major,
                 active_image_version->iv_minor,
                 active_image_version->iv_revision,
                 active_image_version->iv_build_num));
    }

    return result;

cleanup:
    /* On create error, OTA Agent won't call otaPal_Abort()/
     * otaPal_CloseFile() for cleanup. Call otaPal_Abort() manually. */
    otaPal_Abort(C);

    return result;
}


/* Abort receiving the specified OTA update by closing the file. */

OtaPalStatus_t otaPal_Abort( OtaFileContext_t * const C )
{
    OtaPalStatus_t result = OTA_PAL_COMBINE_ERR( OtaPalSuccess, 0 );

    /* Unnecessary to check C for NULL because OTA Agent has guaranteed */

    LogInfo(("otaPal_Abort()..."));

    /* Don't set image state to invalid in otaPal_Abort()
     *
     * otaPal_Abort() can get called arbitrarily by OTA Agent. We don't set
     * image state to invalid here to avoid breaking post-reboot OTA process,
     * where image state will set to OtaPalImageStatePendingCommit/
     * OtaImageStateAccepted.
     */
    //nvImgUpgSt_setImageState(OtaPalImageStateInvalid);

    /* Check for null file handle since we may call this before a file is actually opened. */
    OTA_OperationDescriptor_t *pxCurOTADesc = (OTA_OperationDescriptor_t *) C->pFile;

    /* Deinit secondary bd */
    if (pxCurOTADesc && pxCurOTADesc->fwu_stage.secondary_bd) {
        if (pxCurOTADesc->fwu_stage.secondary_bd_readblock) {
            free(pxCurOTADesc->fwu_stage.secondary_bd_readblock);
            pxCurOTADesc->fwu_stage.secondary_bd_readblock = NULL;
            pxCurOTADesc->fwu_stage.secondary_bd_readblock_size = 0;
        }

        if (pxCurOTADesc->fwu_stage.secondary_bd_progunit) {
            free(pxCurOTADesc->fwu_stage.secondary_bd_progunit);
            pxCurOTADesc->fwu_stage.secondary_bd_progunit = NULL;
            pxCurOTADesc->fwu_stage.secondary_bd_progunit_size = 0;
        }

        if (pxCurOTADesc->fwu_stage.secondary_bd_inited) {
            pxCurOTADesc->fwu_stage.secondary_bd->deinit();
            pxCurOTADesc->fwu_stage.secondary_bd_inited = false;
        }
        pxCurOTADesc->fwu_stage.secondary_bd = NULL;
    }

    /* Unlink OTA Agent/OTA PAL */
    prvContextUnlink( C );

    return result;
}

/* Write a block of data to the specified file. 
   Returns the number of bytes written on success or negative error code.
*/
int16_t otaPal_WriteBlock( OtaFileContext_t * const C,
                           uint32_t ulOffset,
                           uint8_t * const pacData,
                           uint32_t ulBlockSize )
{
    /* Unnecessary to check C for NULL because OTA Agent has guaranteed */

    /* Validate OTA Agent/OTA PAL link */
    if (!prvContextValidate(C)) {
        LogError(("Invalid OTA Agent/OTA PAL link"));
        return -1;
    }

    LogInfo(("otaPal_WriteBlock(offset=%d, size=%d, total=%d)...",
             ulOffset,
             ulBlockSize,
             C->fileSize));

    OTA_OperationDescriptor_t *pxCurOTADesc = (OTA_OperationDescriptor_t *) C->pFile;

    /* Catch MCUBOOT header at offset 0 and store it in buffer for later use. */
    if (ulOffset == 0) {
        LogInfo(("Cache MCUBOOT header for later use"));

        if (ulBlockSize < sizeof(struct image_header)) {
            LogError(("failed to cache MCUBOOT header for later use at first write: write size=%d",
                     ulBlockSize));
            return -1;
        }

        memcpy(&(pxCurOTADesc->fwu_stage.image_header),
               pacData,
               sizeof(struct image_header));

        if (pxCurOTADesc->fwu_stage.image_header.ih_magic != IMAGE_MAGIC) {
            LogError(("Invalid MCUBOOT header magic"));
            return -1;
        }
        
        LogInfo(("Image header: padded header size=%d, image size=%d, protected TLV size=%d",
                 pxCurOTADesc->fwu_stage.image_header.ih_hdr_size,
                 pxCurOTADesc->fwu_stage.image_header.ih_img_size,
                 pxCurOTADesc->fwu_stage.image_header.ih_protect_tlv_size));

        struct image_version *stage_image_version = &(pxCurOTADesc->fwu_stage.image_header.ih_ver);
        LogInfo(("Stage image version: %d.%d.%d+%d",
                 stage_image_version->iv_major,
                 stage_image_version->iv_minor,
                 stage_image_version->iv_revision,
                 stage_image_version->iv_build_num));

        /* Save stage version in NV to check installed or not on reboot */
        if (!nvImgUpgSt_setStageVersion(&pxCurOTADesc->fwu_stage.image_header.ih_ver)) {
            LogError(("nvImgUpgSt_setStageVersion() failed"));
            return -1;
        }
    }

    /* secondary bd ready for program? */
    if (pxCurOTADesc->fwu_stage.secondary_bd == NULL ||
        !pxCurOTADesc->fwu_stage.secondary_bd_inited) {
        LogError(("Secondary BlockDevice not ready for program"));
        return -1;
    }

    /* Write through BlockDevice program() */

    MBED_ASSERT(pxCurOTADesc->fwu_stage.secondary_bd_progunit);
    MBED_ASSERT(pxCurOTADesc->fwu_stage.secondary_bd_progunit_size);

    /* Program date which align on program unit boundary */
    uint8_t *fwu_data = pacData;
    size_t fwu_offset = ulOffset;
    size_t fwu_todo = ulBlockSize - (ulBlockSize % pxCurOTADesc->fwu_stage.secondary_bd_progunit_size);
    int rc = 0;

    rc = pxCurOTADesc->fwu_stage.secondary_bd->program(fwu_data,
                                                       fwu_offset,
                                                       fwu_todo);
    if (rc != 0) {
        LogError(("Secondary BlockDevice program(addr=%d, size=%d) failed: %d",
                  fwu_offset, fwu_todo, rc));
        return -1;
    }
    fwu_data += fwu_todo;
    fwu_offset += fwu_todo;

    /* Program last data which doesn't align on program unit boundary */
    fwu_todo = ulBlockSize - (fwu_offset - ulOffset);
    MBED_ASSERT(pxCurOTADesc->fwu_stage.secondary_bd_progunit_size > fwu_todo);
    if (fwu_todo) {
        if ((ulOffset + ulBlockSize) < C->fileSize) {
            LogInfo(("otaPal_WriteBlock(offset=%d, size=%d, total=%d) failed: unaligned block size not last block",
                     ulOffset, ulBlockSize, C->fileSize));
            return -1;
        }

        /* Fake last program unit is erased */
        memset(pxCurOTADesc->fwu_stage.secondary_bd_progunit,
               pxCurOTADesc->fwu_stage.secondary_bd->get_erase_value(),
               pxCurOTADesc->fwu_stage.secondary_bd_progunit_size);

        /* Move unaligned data to last program unit */
        uint8_t *fwu_data_last = (uint8_t *) pxCurOTADesc->fwu_stage.secondary_bd_progunit;
        size_t fwu_offset_last = fwu_offset;
        size_t fwu_todo_last = pxCurOTADesc->fwu_stage.secondary_bd_progunit_size;
        memcpy(fwu_data_last, fwu_data, fwu_todo);
        fwu_data += fwu_todo;
        fwu_offset += fwu_todo;

        /* Program last program unit: actual + erased */
        rc = pxCurOTADesc->fwu_stage.secondary_bd->program(fwu_data_last,
                                                           fwu_offset_last,
                                                           fwu_todo_last);
        if (rc != 0) {
            LogError(("Secondary BlockDevice program(addr=%d, size=%d) failed: %d",
                      fwu_offset_last, fwu_todo_last, rc));
            return -1;
        }
    }

    return (fwu_offset - ulOffset);
}

extern "C" const char aws_codeVerCrt[];

/* Close the specified file. This shall authenticate the file if it is marked as secure. */

OtaPalStatus_t otaPal_CloseFile( OtaFileContext_t * const C )
{
    OtaPalStatus_t result = OTA_PAL_COMBINE_ERR( OtaPalSuccess, 0 );

    /* Unnecessary to check C for NULL because OTA Agent has guaranteed */

    LogInfo(("otaPal_CloseFile()..."));

    /* Validate OTA Agent/OTA PAL link */
    if (!prvContextValidate(C)) {
        LogError(("Invalid OTA Agent/OTA PAL link"));
        result = OTA_PAL_COMBINE_ERR( OtaPalUninitialized, -1 );
        return result;
    }

    OTA_OperationDescriptor_t *pxCurOTADesc = (OTA_OperationDescriptor_t *) C->pFile;

    /* Always use predefined PKCS11 code verification public key label */
    if (C->pCertFilepath && C->certFilePathMaxSize) {
        LogWarn(("Ignore certificate file pathname %.*s. Use predefined PKCS11 label %.*s instead",
                 C->certFilePathMaxSize,
                 C->pCertFilepath,
                 sizeof(pkcs11configLABEL_CODE_VERIFICATION_KEY) - 1,
                 pkcs11configLABEL_CODE_VERIFICATION_KEY));
    }

    /* Verify signature */
    if (!otaUtil_VerSig(C)) {
        result = OTA_PAL_COMBINE_ERR( OtaPalSignatureCheckFailed, -1 );
        goto cleanup;
    }

    /* Deinit secondary bd */
    if (pxCurOTADesc && pxCurOTADesc->fwu_stage.secondary_bd) {
        if (pxCurOTADesc->fwu_stage.secondary_bd_readblock) {
            free(pxCurOTADesc->fwu_stage.secondary_bd_readblock);
            pxCurOTADesc->fwu_stage.secondary_bd_readblock = NULL;
            pxCurOTADesc->fwu_stage.secondary_bd_readblock_size = 0;
        }

        if (pxCurOTADesc->fwu_stage.secondary_bd_progunit) {
            free(pxCurOTADesc->fwu_stage.secondary_bd_progunit);
            pxCurOTADesc->fwu_stage.secondary_bd_progunit = NULL;
            pxCurOTADesc->fwu_stage.secondary_bd_progunit_size = 0;
        }

        if (pxCurOTADesc->fwu_stage.secondary_bd_inited) {
            pxCurOTADesc->fwu_stage.secondary_bd->deinit();
            pxCurOTADesc->fwu_stage.secondary_bd_inited = false;
        }
        pxCurOTADesc->fwu_stage.secondary_bd = NULL;
    }

    /* We keep OTA Agent/OTA PAL linked even after otaPal_CloseFile(). The
     * link may or may not be necessary in post-otaPal_CloseFile() like
     * otaPal_ActivateNewImage(). */

    return result;

cleanup:

    /* otaPal_CloseFile() handles clean-up halfway due to midway failure.
     * Call otaPal_Abort() to complete the clean-up. */
    otaPal_Abort(C);

    return result;
}

OtaPalStatus_t otaPal_ResetDevice( OtaFileContext_t * const C )
{
    ( void ) C;

    LogInfo(("System will reboot in 3 seconds..."));
    mbed_event_queue()->call_in(std::chrono::seconds(3), NVIC_SystemReset);

    while (1);

    /* We shouldn't actually get here if the board supports the auto reset.
     * But, it doesn't hurt anything if we do although someone will need to
     * reset the device for the new image to boot. */

    return OTA_PAL_COMBINE_ERR( OtaPalSuccess, 0 );
}

OtaPalStatus_t otaPal_ActivateNewImage( OtaFileContext_t * const C )
{
    OtaPalStatus_t result = OTA_PAL_COMBINE_ERR( OtaPalSuccess, 0 );

    ( void ) C;

    LogInfo(("otaPal_ActivateNewImage()..."));

    /* Marks the image with index 0 in the secondary slot as pending. On the next
     * reboot, the system will perform a one-time boot of the the secondary slot image. */
    if (boot_set_pending(0) != 0) {
        LogError(("boot_set_pending(0) failed"));
        result = OTA_PAL_COMBINE_ERR( OtaPalActivateFailed, -1 );
        return result;
    }

    /* OTA flow requires reboot. */

    /* Indicate not reboot yet for install */
    if (!nvImgUpgSt_setInstallRebooted(false)) {
        LogError(("nvImgUpgSt_setInstallRebooted(false) failed"));
        result = OTA_PAL_COMBINE_ERR( OtaPalActivateFailed, -1 );
        return result;
    }

    return otaPal_ResetDevice(C);
}

/*
 * Set the final state of the last transferred (final) OTA file (or bundle).
 * The state of the OTA image is stored in FMC header.
 */

OtaPalStatus_t otaPal_SetPlatformImageState( OtaFileContext_t * const C,
                                             OtaImageState_t eState )
{
    OtaPalStatus_t result = OTA_PAL_COMBINE_ERR( OtaPalSuccess, 0 );

    ( void ) C;

    if ((eState == OtaImageStateUnknown) || (eState > OtaLastImageState)) {
        LogError(("Invalid image state provided: %d", eState));
        result = OTA_PAL_COMBINE_ERR( OtaPalBadImageState, -1 );
        return result;
    }

    LogInfo(("otaPal_SetPlatformImageState(%d)...", eState));

    bool confirmed = false;

    switch (eState) {
    case OtaImageStateTesting:
    case OtaImageStateAccepted:
        if (nvImgUpgSt_installed(&confirmed)) {
            if (OtaImageStateTesting == eState) {
                /* Some MCUboot upgrade strategies like RAM_LOAD and OVERWRITE_ONLY
                 * do not support image revert. confirmed will always be true when
                 * installed is true. In these cases, always set OTA PAL image state
                 * to OtaPalImageStatePendingCommit to match OTA Agent flow. */
                if (!nvImgUpgSt_setImageState(OtaPalImageStatePendingCommit)) {
                    LogError(("otaPal_SetPlatformImageState(%d) failed: nvImgUpgSt_setImageState(%d) failed", eState, OtaPalImageStatePendingCommit));
                    result = OTA_PAL_COMBINE_ERR( OtaPalCommitFailed, -1 );
                    return result;
                }
            } else {
                /* Marks the image with index 0 in the primary slot as confirmed.  The system
                 * will continue booting into the image in the primary slot until told to boot
                 * from a different slot. */
                if (boot_set_confirmed() != 0) {
                    LogError(("otaPal_SetPlatformImageState(%d) failed: boot_set_confirmed() failed", eState));
                    result = OTA_PAL_COMBINE_ERR( OtaPalCommitFailed, -1 );
                    return result;
                }
                if (!nvImgUpgSt_setImageState(OtaPalImageStateValid)) {
                    LogError(("otaPal_SetPlatformImageState(%d) failed: nvImgUpgSt_setImageState(%d) failed", eState, OtaPalImageStateValid));
                    result = OTA_PAL_COMBINE_ERR( OtaPalCommitFailed, -1 );
                    return result;
                }
            }
        } else {
            LogError(("otaPal_SetPlatformImageState(%d) failed: Not installed by MCUboot", eState));
            result = OTA_PAL_COMBINE_ERR( OtaPalCommitFailed, -1 );
            return result;
        }
        break;

    case OtaImageStateRejected:
    case OtaImageStateAborted:
        if (nvImgUpgSt_installed(&confirmed)) {
            /* MCUboot image_ok having set, rollback is infeasible. */
            if (confirmed) {
                LogError(("otaPal_SetPlatformImageState(%d) failed: Roll back failed: MCUboot image_ok has set", eState));
                if (OtaImageStateRejected == eState) {
                    result = OTA_PAL_COMBINE_ERR( OtaPalRejectFailed, -1 );
                } else {
                    result = OTA_PAL_COMBINE_ERR( OtaPalAbortFailed, -1 );
                }
                return result;
            }

            /* Expect reboot for revert swap by MCUboot */
        } else {
            otaPal_Abort(C);
            nvImgUpgSt_setImageState(OtaPalImageStateInvalid);
        }
        break;

    default:
        LogError(("otaPal_SetPlatformImageState(%d) failed: Unknown state provided", eState));
        result = OTA_PAL_COMBINE_ERR( OtaPalBadImageState, -1 );
        return result;
    }

    /* Resultant image state */
    OtaPalImageState_t imageState = OtaPalImageStateUnknown;
    if (!nvImgUpgSt_imageState(&imageState)) {
        imageState = OtaPalImageStateUnknown;
    }
    LogInfo(("otaPal_SetPlatformImageState(%d)->%d", eState, imageState));

    return result;
}

/* Get the state of the currently running image.
 *
 * This is simulated by looking for and reading the state from
 * FMC Boot Image Header.
 *
 * We read this at OTA_Init time so we can tell if the MCU image is in self
 * test mode. If it is, we expect a successful connection to the OTA services
 * within a reasonable amount of time. If we don't satisfy that requirement,
 * we assume there is something wrong with the firmware and reset the device,
 * causing it to rollback to the previous code. On Windows, this is not
 * fully simulated as there is no easy way to reset the simulated device.
 */
OtaPalImageState_t otaPal_GetPlatformImageState( OtaFileContext_t * const C )
{
    ( void ) C;

    OtaPalImageState_t imageState = OtaPalImageStateUnknown;
    if (!nvImgUpgSt_imageState(&imageState)) {
        imageState = OtaPalImageStateUnknown;
    }

    LogInfo(("otaPal_GetPlatformImageState(): %d", imageState));

    return imageState;
}

/*-----------------------------------------------------------*/

/**
 * \brief   Get signature verification certificate
 *
 * \param   p_cred      On output, pointer to signature verification certificate.
 * \param   p_cred_size On output, pointer to size of \p p_cred in bytes, including
 *                      terminating \c NULL byte in case of PEM encoded data.
 *
 * \return              \c true for success, or \c false for failure
 *
 * \note                On success, \param p_cred is allocated by malloc() and user
 *                      is responsible for deallocating it through free().
 */
static bool otaUtil_sigVerCrt(uint8_t **p_cred, size_t *p_cred_size)
{
    const char *cred_key = KV_DEF_FQ_KEY(pkcs11configLABEL_CODE_VERIFICATION_KEY);
    uint8_t *cred_value = NULL;
    size_t cred_value_size = 0;

    do {
        /* Key info */
        kv_info_t info;
        auto kv_status = kv_get_info(cred_key, &info);
        if (kv_status != MBED_SUCCESS) {
            LogError(("kv_get_info: %s failed: %d\r\n", cred_key, MBED_GET_ERROR_CODE(kv_status)));
            break;
        }

        cred_value = (uint8_t *) malloc(info.size);
        kv_status = kv_get(cred_key, cred_value, info.size, &cred_value_size);
        if (kv_status != MBED_SUCCESS) {
            LogError(("kv_get: %s failed: %d\r\n", cred_key, MBED_GET_ERROR_CODE(kv_status)));
            break;
        }
        if (cred_value_size != info.size) {
            LogError(("kv_get: %s failed: expected value size: %d but actual: %d\r\n", cred_key, info.size, cred_value_size));
            break;
        }

        if (p_cred) {
            *p_cred = (uint8_t *) cred_value;
        }
        if (p_cred_size) {
            *p_cred_size = cred_value_size;
        }
        
        return true;

    } while (0);

    if (cred_value) {
        free(cred_value);
        cred_value = NULL;
    }
    cred_value_size = 0;

    return false;
}

/**
 * \brief   Verify signature of firmware upgrade image
 */
static bool otaUtil_VerSig(OtaFileContext_t * const C)
{
    bool sig_ok = false;
    void *pvSigVerifyContext = NULL;
    uint8_t *fwu_data = NULL;
    size_t fwu_offset;
    size_t fwu_todo;
    uint8_t *p_cred = NULL;
    size_t cred_size = 0;

    OTA_OperationDescriptor_t *pxCurOTADesc = (OTA_OperationDescriptor_t *) C->pFile;

    /* Initialize */
    LogInfo(("Code signature size: %d", C->pSignature->size));
    if (!CRYPTO_SignatureVerificationStart(&pvSigVerifyContext,
                                           cryptoASYMMETRIC_ALGORITHM_ECDSA,
                                           cryptoHASH_ALGORITHM_SHA256)) {
        LogError(("CRYPTO_SignatureVerificationStart() failed"));
        goto cleanup;
    }

    /* secondary bd ready for read? */
    if (pxCurOTADesc->fwu_stage.secondary_bd == NULL ||
        !pxCurOTADesc->fwu_stage.secondary_bd_inited) {
        LogError(("Secondary BlockDevice not ready for read"));
        goto cleanup;
    }

    /* Read from secondary bd to calculate image digest */
    MBED_ASSERT(pxCurOTADesc->fwu_stage.secondary_bd_readblock);
    MBED_ASSERT(pxCurOTADesc->fwu_stage.secondary_bd_readblock_size);
    fwu_data = (uint8_t *) pxCurOTADesc->fwu_stage.secondary_bd_readblock;
    fwu_offset = 0;
    while (fwu_offset < C->fileSize) {
        fwu_todo = C->fileSize - fwu_offset;
        if (fwu_todo > pxCurOTADesc->fwu_stage.secondary_bd_readblock_size) {
            fwu_todo = pxCurOTADesc->fwu_stage.secondary_bd_readblock_size;
        }

        int rc = pxCurOTADesc->fwu_stage.secondary_bd->read(fwu_data,
                                                            fwu_offset,
                                                            fwu_todo);
        if (rc != 0) {
            LogError(("Secondary BlockDevice read(addr=%d, size=%d) failed: %d",
                      fwu_offset, fwu_todo, rc));
            goto cleanup;
        }

        CRYPTO_SignatureVerificationUpdate(pvSigVerifyContext,
                                           fwu_data,
                                           fwu_todo);

        /* Next data */
        fwu_offset += fwu_todo;
    }

#if ENABLE_CODE_VERIFY_BY_PKCS11
    /* Verify signature */
    sig_ok = CRYPTO_SignatureVerificationFinalByPKCS11Label(pvSigVerifyContext,
                                                            (const uint8_t *) pkcs11configLABEL_CODE_VERIFICATION_KEY,
                                                            sizeof(pkcs11configLABEL_CODE_VERIFICATION_KEY) - 1,
                                                            C->pSignature->data, 
                                                            C->pSignature->size);
#else
    /* Get signature verification certificate */
    p_cred = NULL;
    cred_size = 0;
    if (!otaUtil_sigVerCrt(&p_cred, &cred_size)) {
        LogError(("otaUtil_sigVerCrt() failed"));
        goto cleanup;
    }

    /* Verify signature */
    sig_ok = CRYPTO_SignatureVerificationFinal(pvSigVerifyContext,
                                               (const char *) p_cred,
                                               cred_size,
                                               C->pSignature->data, 
                                               C->pSignature->size);
    free(p_cred);
    p_cred = NULL;
    cred_size = 0;
#endif
    /* Set to NULL to indicate CRYPTO_SignatureVerificationFinal() or like has called */
    pvSigVerifyContext = NULL;
    if (!sig_ok) {
        LogError(("Code signature verification FAILED"));
        goto cleanup;
    }
    LogInfo(("Code signature verification OK"));

cleanup:

    if (pvSigVerifyContext) {
        CRYPTO_SignatureVerificationFinal(pvSigVerifyContext,
                                          NULL,
                                          0,
                                          NULL,
                                          0);
        pvSigVerifyContext = NULL;
    }

    return sig_ok;
}

/*-----------------------------------------------------------*/

static bool nvImgUpgSt_reset(void)
{
    OTA_NonVolatileImageUpgradeState_t imageUpgradeState;
    memset(&imageUpgradeState, 0x00, sizeof(OTA_NonVolatileImageUpgradeState_t));

    return nvImgUpgSt_setAll(&imageUpgradeState);
}

static bool nvImgUpgSt_setStageVersion(struct image_version *stageVersion)
{
    OTA_NonVolatileImageUpgradeState_t imageUpgradeState;
    if (!nvImgUpgSt_getAll(&imageUpgradeState)) {
        return false;
    }

    memcpy(&(imageUpgradeState.stageVersion),
           stageVersion,
           sizeof(struct image_version));
    imageUpgradeState.stageVersion_valid = true;

    return nvImgUpgSt_setAll(&imageUpgradeState);
}

static bool nvImgUpgSt_setImageState(OtaPalImageState_t imageState)
{
    OTA_NonVolatileImageUpgradeState_t imageUpgradeState;
    if (!nvImgUpgSt_getAll(&imageUpgradeState)) {
        return false;
    }

    imageUpgradeState.imageState = imageState;
    imageUpgradeState.imageState_valid = true;

    return nvImgUpgSt_setAll(&imageUpgradeState);
}

static bool nvImgUpgSt_setInstallRebooted(bool installRebooted)
{
    OTA_NonVolatileImageUpgradeState_t imageUpgradeState;
    if (!nvImgUpgSt_getAll(&imageUpgradeState)) {
        return false;
    }

    imageUpgradeState.installRebooted = installRebooted;
    imageUpgradeState.installRebooted_valid = true;

    return nvImgUpgSt_setAll(&imageUpgradeState);
}

static bool nvImgUpgSt_installed(bool *confirmed)
{
    OTA_NonVolatileImageUpgradeState_t imageUpgradeState;
    if (!nvImgUpgSt_getAll(&imageUpgradeState)) {
        return false;
    }

    if (!imageUpgradeState.installRebooted_valid ||
        !imageUpgradeState.installRebooted) {
        return false;
    }

    if (!imageUpgradeState.stageVersion_valid) {
        return false;
    }

    const struct image_header *active_header = (const struct image_header *) MCUBOOT_PRIMARY_SLOT_START_ADDR;
    const struct image_version *active_version = &(active_header->ih_ver);

    if (0 != memcmp(&(imageUpgradeState.stageVersion),
                    active_version,
                    sizeof(struct image_version))) {
        return false;
    }

    const struct flash_area *fap = NULL;
    uint8_t image_ok = BOOT_FLAG_UNSET;

    if ((flash_area_open(FLASH_AREA_IMAGE_PRIMARY(0), &fap)) != 0) {
        return false;
    }

    /* Get value of image-ok flag of the image to check whether application
     * itself is already confirmed. */
    if (boot_read_image_ok(fap, &image_ok) != 0) {
        goto cleanup;
    }

cleanup:

    if (fap) {
        flash_area_close(fap);
        fap = NULL;
    }

    if (image_ok == BOOT_FLAG_SET) {
        *confirmed = true;
        return true;
    } else {
        *confirmed = false;
        return true;
    }
}

static bool nvImgUpgSt_imageState(OtaPalImageState_t *imageState)
{
    OTA_NonVolatileImageUpgradeState_t imageUpgradeState;
    if (!nvImgUpgSt_getAll(&imageUpgradeState)) {
        return false;
    }

    if (!imageUpgradeState.imageState_valid) {
        return false;
    }

    *imageState = imageUpgradeState.imageState;
    return true;
}

static bool nvImgUpgSt_installRebooted(bool *installRebooted)
{
    OTA_NonVolatileImageUpgradeState_t imageUpgradeState;
    if (!nvImgUpgSt_getAll(&imageUpgradeState)) {
        return false;
    }

    if (!imageUpgradeState.installRebooted_valid) {
        return false;
    }

    *installRebooted = imageUpgradeState.installRebooted;
    return true;
}

static bool nvImgUpgSt_setAll(const OTA_NonVolatileImageUpgradeState_t *imageUpgradeState)
{
    int kv_status = kv_set(KV_DEF_FQ_KEY(OTA_IMAGE_UPDATE_STATE_KEY),
                           imageUpgradeState,
                           sizeof(OTA_NonVolatileImageUpgradeState_t),
                           0);
    if (kv_status != MBED_SUCCESS) {
        return false;
    }

    return true;
}

static bool nvImgUpgSt_getAll(OTA_NonVolatileImageUpgradeState_t *imageUpgradeState)
{
    size_t actual_size = 0;

    int kv_status = kv_get(KV_DEF_FQ_KEY(OTA_IMAGE_UPDATE_STATE_KEY),
                           imageUpgradeState,
                           sizeof(OTA_NonVolatileImageUpgradeState_t),
                           &actual_size);
    if (kv_status != MBED_SUCCESS) {
        return false;
    }
    if (actual_size != sizeof(OTA_NonVolatileImageUpgradeState_t)) {
        return false;
    }

    return true;
}
