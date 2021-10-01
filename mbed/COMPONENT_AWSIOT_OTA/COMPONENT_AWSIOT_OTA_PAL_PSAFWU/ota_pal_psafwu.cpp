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

/* OTA PAL implementation for NuMaker Mbed platform, using PSA FWU. */

/* Standard includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/* Mbed includes */
#include "mbed.h"
#include "mbed_trace.h"

/* PSA includes */
#include "psa/crypto.h"
#include "psa/update.h"

/* OTA PAL includes */
#include "ota_pal_psafwu.h"

/* PKCS11 includes */
#include "core_pkcs11_config.h"
#include "core_pkcs11.h"
#include "iot_pkcs11_psa_object_management.h"
#include "iot_pkcs11_psa_input_format.h"
#include "iot_crypto.h"

/* Test code verification by certificate */
#define     NU_TEST_CODE_VERIFY_BY_CERTIFICATE       0

/* Specify the OTA signature algorithm we support on this platform. */
const char OTA_JsonFileSignatureKey[ OTA_FILE_SIG_KEY_STR_MAX_LENGTH ] = "sig-sha256-ecdsa";

/*-----------------------------------------------------------*/

/*****************************************************************************/
/* MCUBOOT                                                                   */
/*****************************************************************************/

#define IMAGE_MAGIC                 0x96f3b83d
#define IMAGE_HEADER_SIZE           32

/**
 * MCUBOOT Image version.
 */
typedef struct image_version {
    uint8_t iv_major;
    uint8_t iv_minor;
    uint16_t iv_revision;
    uint32_t iv_build_num;
} image_version_t;

/**
 * MCUBOOT Image header. All fields are in little endian byte order.
 */
typedef struct image_header {
    uint32_t ih_magic;
    uint32_t ih_load_addr;
    uint16_t ih_hdr_size;           /* Size of image header (bytes). */
    uint16_t ih_protect_tlv_size;   /* Size of protected TLV area (bytes). */
    uint32_t ih_img_size;           /* Does not include header. */
    uint32_t ih_flags;              /* IMAGE_F_[...]. */
    image_version_t ih_ver;
    uint32_t _pad1;
} image_header_t;

/**
 * MCUBOOT Image TLV header.  All fields in little endian.
 */
typedef struct image_tlv_info {
    uint16_t it_magic;
    uint16_t it_tlv_tot;  /* size of TLV area (including tlv_info header) */
} image_tlv_info_t;

/**
 * MCUBOOT Image trailer TLV format. All fields in little endian.
 */
typedef struct image_tlv {
    uint8_t it_type;   /* IMAGE_TLV_[...]. */
    uint8_t _pad;
    uint16_t it_len;    /* Data length (not including TLV header). */
} image_tlv_t;

#define IMAGE_TLV_INFO_MAGIC        0x6907
#define IMAGE_TLV_PROT_INFO_MAGIC   0x6908
#define IMAGE_TLV_SHA256            0x10   /* SHA256 of image hdr and body */

/*-----------------------------------------------------------*/

/* PSA image ID: active/stage + non-secure */
#define IMAGE_ID_ACTIVE_NONSECURE                                       \
    ((psa_image_id_t) FWU_CALCULATE_IMAGE_ID(FWU_IMAGE_ID_SLOT_ACTIVE,  \
                                             FWU_IMAGE_TYPE_NONSECURE,  \
                                             0))
#define IMAGE_ID_STAGE_NONSECURE                                        \
    ((psa_image_id_t) FWU_CALCULATE_IMAGE_ID(FWU_IMAGE_ID_SLOT_STAGE,   \
                                             FWU_IMAGE_TYPE_NONSECURE,  \
                                             0))

typedef struct
{
    const OtaFileContext_t *    pxOTAFileCtx;       // OTA Agent file context
#if NU_TEST_CODE_VERIFY_BY_CERTIFICATE
    void *                      pvSigVerifyContext_cert;    // Code signature verification context (by certificate)
#endif
    void *                      pvSigVerifyContext;         // Code signature verification context

    /* PSA firmware update context: Active */
    struct psa_fwu_active_s {
        psa_image_info_t        info;
        image_version_t         version;
    } psa_fwu_active;

    /* PSA firmware update context: Stage */
    struct psa_fwu_stage_s {
        psa_image_info_t        info;
        image_header_t          image_header;       // Cached image header on the fly
                                                    // During FWU process, image version is not available
                                                    // through psa_fwu_query(). Acquire from above cached instead.
    } psa_fwu_stage;
} OTA_OperationDescriptor_t;

/* NOTE that this implementation supports only one OTA at a time since it uses a single static instance. */
static OTA_OperationDescriptor_t xCurOTAOpDesc;     // OTA operation in progress

/*-----------------------------------------------------------*/

/* Validate OTA Agent/OTA PAL are linked */
static __inline bool prvContextValidate( OtaFileContext_t * C )
{
    return ((NULL != C) &&
            (NULL != C->pFile) &&
            ((uintptr_t) C == (uintptr_t) ((OTA_OperationDescriptor_t *) C->pFile)->pxOTAFileCtx));
}

/* Unlink OTA Agent/OTA PAL */
static __inline void prvContextUnlink( OtaFileContext_t * C )
{
    if (NULL != C && NULL != C->pFile) {
        ((OTA_OperationDescriptor_t *) C->pFile)->pxOTAFileCtx = NULL;
        C->pFile = NULL;
    }
}

/*-----------------------------------------------------------*/

/* In-storage struct for holding OTA PAL/PSA FWU states which need to be non-volatile to cross reset cycle */
typedef struct {
    /* MCUboot version of stage, non-secure image */
    bool                stageVersion_valid;
    image_version_t     stageVersion;

    /* OTA PAL image state */
    bool                imageState_valid;
    OtaPalImageState_t  imageState;

    /* Flag for install rebooted */
    bool                installRebooted_valid;
    bool                installRebooted;
} OTA_NonVolatileImageUpgradeState_t;

/* Routines to operate in-storage OTA_NonVolatileImageUpgradeState_t struct */
static bool nvImgUpgSt_reset(void);
static bool nvImgUpgSt_setStageVersion(image_version_t *stageVersion);
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

    /* Initialize signature verification process
     *
     * PSA FWU doesn't support/allow image read-back after write. We need to
     * calculate image digest on the fly.
     */
#if NU_TEST_CODE_VERIFY_BY_CERTIFICATE
    CRYPTO_SignatureVerificationStart(&pxCurOTADesc->pvSigVerifyContext_cert,
                                      cryptoASYMMETRIC_ALGORITHM_ECDSA,
                                      cryptoHASH_ALGORITHM_SHA256);
#endif
    if (!CRYPTO_SignatureVerificationStart(&pxCurOTADesc->pvSigVerifyContext,
                                           cryptoASYMMETRIC_ALGORITHM_ECDSA,
                                           cryptoHASH_ALGORITHM_SHA256)) {
        LogError(("CRYPTO_SignatureVerificationStart() failed"));
        result = OTA_PAL_COMBINE_ERR( OtaPalRxFileCreateFailed, -1 );
        goto cleanup;
    }

    /* Get active image's version */
    {
        psa_status_t status = psa_fwu_query(IMAGE_ID_ACTIVE_NONSECURE,
                                            &(pxCurOTADesc->psa_fwu_active.info));
        if (PSA_SUCCESS != status) {
            LogError(("psa_fwu_query() failed: %d", status));
            result = OTA_PAL_COMBINE_ERR( OtaPalRxFileCreateFailed, -1 );
            goto cleanup;
        }
        /* psa_image_version_t and image_version_t are the same struct format, so straight memcpy(). */
        memcpy(&(pxCurOTADesc->psa_fwu_active.version),
               &(pxCurOTADesc->psa_fwu_active.info.version),
               sizeof(pxCurOTADesc->psa_fwu_active.version));

        image_version_t *active_image_version = &(pxCurOTADesc->psa_fwu_active.version);
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

    /* Abort PSA FWU process */
    psa_fwu_abort(IMAGE_ID_STAGE_NONSECURE);

    /* Check for null file handle since we may call this before a file is actually opened. */
    OTA_OperationDescriptor_t *pxCurOTADesc = (OTA_OperationDescriptor_t *) C->pFile;

    /* Abort signature verification process */
    if (pxCurOTADesc && pxCurOTADesc->pvSigVerifyContext) {
#if NU_TEST_CODE_VERIFY_BY_CERTIFICATE
        CRYPTO_SignatureVerificationFinal(pxCurOTADesc->pvSigVerifyContext_cert,
                                          NULL,
                                          0,
                                          NULL,
                                          0);
#endif
        CRYPTO_SignatureVerificationFinal(pxCurOTADesc->pvSigVerifyContext,
                                          NULL,
                                          0,
                                          NULL,
                                          0);
        /* Set to NULL for safe after CRYPTO_SignatureVerificationFinal()-like gets called */
        pxCurOTADesc->pvSigVerifyContext = NULL;
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

        if (ulBlockSize < sizeof(image_header_t)) {
            LogError(("failed to cache MCUBOOT header for later use at first write: write size=%d",
                     ulBlockSize));
            return -1;
        }

        memcpy(&(pxCurOTADesc->psa_fwu_stage.image_header), pacData, sizeof(image_header_t));

        if (pxCurOTADesc->psa_fwu_stage.image_header.ih_magic != IMAGE_MAGIC) {
            LogError(("Invalid MCUBOOT header magic"));
            return -1;
        }
        
        LogInfo(("Image header: padded header size=%d, image size=%d, protected TLV size=%d",
                 pxCurOTADesc->psa_fwu_stage.image_header.ih_hdr_size,
                 pxCurOTADesc->psa_fwu_stage.image_header.ih_img_size,
                 pxCurOTADesc->psa_fwu_stage.image_header.ih_protect_tlv_size));

        image_version_t *stage_image_version = &(pxCurOTADesc->psa_fwu_stage.image_header.ih_ver);
        LogInfo(("Stage image version: %d.%d.%d+%d",
                 stage_image_version->iv_major,
                 stage_image_version->iv_minor,
                 stage_image_version->iv_revision,
                 stage_image_version->iv_build_num));

        /* Save stage version in NV to check installed or not on reboot */
        if (!nvImgUpgSt_setStageVersion(&pxCurOTADesc->psa_fwu_stage.image_header.ih_ver)) {
            LogError(("nvImgUpgSt_setStageVersion() failed"));
            return -1;
        }
    }

    /* Write through psa_fwu_write(), with max block size PSA_FWU_MAX_BLOCK_SIZE */
    const uint8_t *fwu_src_pos = pacData;
    const uint8_t *fwu_src_end = pacData + ulBlockSize;
    size_t fwu_dst_pos = ulOffset;
    size_t fwu_todo;
    psa_status_t status;

    while (fwu_src_pos < fwu_src_end) {
        fwu_todo = fwu_src_end - fwu_src_pos;
        if (fwu_todo > PSA_FWU_MAX_BLOCK_SIZE) {
            fwu_todo = PSA_FWU_MAX_BLOCK_SIZE;
        }

        status = psa_fwu_write(IMAGE_ID_STAGE_NONSECURE,
                               fwu_dst_pos,
                               fwu_src_pos,
                               fwu_todo);
        if (PSA_SUCCESS != status) {
            LogError(("psa_fwu_write(offset=%d, size=%d) failed: %d",
                      fwu_dst_pos, fwu_todo, status));
            return -1;
        }

        /* Calculate image digest on the fly */
#if NU_TEST_CODE_VERIFY_BY_CERTIFICATE
        CRYPTO_SignatureVerificationUpdate(pxCurOTADesc->pvSigVerifyContext_cert,
                                           fwu_src_pos,
                                           fwu_todo);
#endif
        CRYPTO_SignatureVerificationUpdate(pxCurOTADesc->pvSigVerifyContext,
                                           fwu_src_pos,
                                           fwu_todo);

        /* Next block */
        fwu_dst_pos += fwu_todo;
        fwu_src_pos += fwu_todo;
    }

    return (fwu_dst_pos - ulOffset);
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

    LogInfo(("Code signature size: %d", C->pSignature->size));

#if NU_TEST_CODE_VERIFY_BY_CERTIFICATE
    bool sig_ok_cert = CRYPTO_SignatureVerificationFinal(pxCurOTADesc->pvSigVerifyContext_cert,
                                                         (const char *) aws_codeVerCrt,
                                                         strlen(aws_codeVerCrt) + 1,
                                                         C->pSignature->data, 
                                                         C->pSignature->size);
    LogInfo(("Code signature verification (by certificate) %s", sig_ok_cert ? "OK" : "FAILED"));
#endif
    bool sig_ok = CRYPTO_SignatureVerificationFinalByPKCS11Label(pxCurOTADesc->pvSigVerifyContext,
                                                                 (const uint8_t *) pkcs11configLABEL_CODE_VERIFICATION_KEY,
                                                                 sizeof(pkcs11configLABEL_CODE_VERIFICATION_KEY) - 1,
                                                                 C->pSignature->data, 
                                                                 C->pSignature->size);
    /* Set to NULL for safe after CRYPTO_SignatureVerificationFinal()-like gets called */
    pxCurOTADesc->pvSigVerifyContext = NULL;
    if (!sig_ok) {
        LogError(("Code signature verification FAILED"));
        result = OTA_PAL_COMBINE_ERR( OtaPalSignatureCheckFailed, -1 );
        return result;
    }
    LogInfo(("Code signature verification OK"));

    /* We keep OTA Agent/OTA PAL linked even after otaPal_CloseFile(). The
     * link may or may not be necessary in post-otaPal_CloseFile() like
     * otaPal_ActivateNewImage(). */

    return result;
}

OtaPalStatus_t otaPal_ResetDevice( OtaFileContext_t * const C )
{
    ( void ) C;

    LogInfo(("System will reboot in 3 seconds..."));
#if 1
    ThisThread::sleep_for(std::chrono::seconds(3));
    psa_status_t status = psa_fwu_request_reboot();
    if (PSA_SUCCESS != status) {
        LogError(("psa_fwu_request_reboot() failed: %d", status));
    }
#else
    mbed_event_queue()->call_in(std::chrono::seconds(3), NVIC_SystemReset);
#endif

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

    psa_image_id_t          dependency_uuid;
    psa_image_version_t     dependency_version;

    psa_status_t status = psa_fwu_install(IMAGE_ID_STAGE_NONSECURE,
                                          &dependency_uuid,
                                          &dependency_version);
    if (PSA_SUCCESS != status && PSA_SUCCESS_REBOOT != status) {
        LogError(("psa_fwu_install() failed: %d", status));
        result = OTA_PAL_COMBINE_ERR( OtaPalActivateFailed, -1 );
        return result;
    }

    /* OTA flow requires reboot, so always reboot even with non-PSA_SUCCESS_REBOOT. */

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
                psa_status_t status = psa_fwu_accept(IMAGE_ID_ACTIVE_NONSECURE);
                if (PSA_SUCCESS != status) {
                    LogError(("otaPal_SetPlatformImageState(%d) failed: psa_fwu_accept() failed: %d", eState, status));
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

static bool nvImgUpgSt_reset(void)
{
    OTA_NonVolatileImageUpgradeState_t imageUpgradeState;
    memset(&imageUpgradeState, 0x00, sizeof(OTA_NonVolatileImageUpgradeState_t));

    return nvImgUpgSt_setAll(&imageUpgradeState);
}

static bool nvImgUpgSt_setStageVersion(image_version_t *stageVersion)
{
    OTA_NonVolatileImageUpgradeState_t imageUpgradeState;
    if (!nvImgUpgSt_getAll(&imageUpgradeState)) {
        return false;
    }

    memcpy(&(imageUpgradeState.stageVersion),
           stageVersion,
           sizeof(image_version_t));
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

    psa_image_info_t active_info;
    psa_status_t status = psa_fwu_query(IMAGE_ID_ACTIVE_NONSECURE,
                                        &active_info);
    if (PSA_SUCCESS != status) {
        return false;
    }

    image_version_t active_version;
    /* psa_image_version_t and image_version_t are the same struct format, so straight memcpy(). */
    memcpy(&active_version,
           &(active_info.version),
           sizeof(active_info.version));

    if (0 != memcmp(&(imageUpgradeState.stageVersion),
                    &active_version,
                    sizeof(active_version))) {
        return false;
    }

    switch (active_info.state) {
    case PSA_IMAGE_PENDING_INSTALL:
        /* MCUboot image_ok unset */
        *confirmed = false;
        return true;

    case PSA_IMAGE_INSTALLED:
        /* MCUboot image_ok set */
        *confirmed = true;
        return true;
        
    default:
        return false;
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
    psa_status_t status = psa_ps_set(PSA_OTA_IMAGE_UPDATE_STATE_UID,
                                     sizeof(OTA_NonVolatileImageUpgradeState_t),
                                     imageUpgradeState,
                                     PSA_STORAGE_FLAG_NONE);
    if (PSA_SUCCESS != status) {
        return false;
    }

    return true;
}

static bool nvImgUpgSt_getAll(OTA_NonVolatileImageUpgradeState_t *imageUpgradeState)
{
    size_t data_length = 0;
    psa_status_t status = psa_ps_get(PSA_OTA_IMAGE_UPDATE_STATE_UID,
                                     0,
                                     sizeof(OTA_NonVolatileImageUpgradeState_t),
                                     imageUpgradeState,
                                     &data_length);
    if (PSA_SUCCESS != status) {
        return false;
    }
    if (sizeof(OTA_NonVolatileImageUpgradeState_t) != data_length) {
        return false;
    }

    return true;
}
