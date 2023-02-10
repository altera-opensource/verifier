/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2022 Intel Corporation. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * **************************************************************************
 *
 */

package com.intel.bkp.core.endianness;

public enum EndiannessStructureFields {
    /* =========== PSG Block0Entry =========== */
    BLOCK0_ENTRY_MAGIC,
    BLOCK0_LENGTH_OFFSET,
    BLOCK0_DATA_LEN,
    BLOCK0_SIG_LEN,
    BLOCK0_SHA_LEN,
    BLOCK0_RESERVED,

    /* =========== PSG CancellableBlock0Entry =========== */
    CANCELLABLE_BLOCK0_ENTRY_MAGIC,
    CANCELLABLE_BLOCK0_LENGTH_OFFSET,
    CANCELLABLE_BLOCK0_DATA_LEN,
    CANCELLABLE_BLOCK0_SIG_LEN,
    CANCELLABLE_BLOCK0_SHA_LEN,
    CANCELLABLE_BLOCK0_META_MAGIC,
    CANCELLABLE_BLOCK0_CANCELLATION_ID,

    /* =========== PSG Public Key =========== */
    PSG_PUB_KEY_MAGIC,
    PSG_PUB_KEY_SIZE_X,
    PSG_PUB_KEY_SIZE_Y,
    PSG_PUB_KEY_CURVE_MAGIC,
    PSG_PUB_KEY_PERMISSIONS,
    PSG_PUB_KEY_CANCELLATION,

    /* =========== PSG signature =========== */
    PSG_SIG_MAGIC,
    PSG_SIG_SIZE_R,
    PSG_SIG_SIZE_S,
    PSG_SIG_HASH_MAGIC,

    /* =========== PSG Certificate Root Entry =========== */
    PSG_CERT_ROOT_MAGIC,
    PSG_CERT_ROOT_LENGTH_OFFSET,
    PSG_CERT_ROOT_DATA_LEN,
    PSG_CERT_ROOT_SIG_LEN,
    PSG_CERT_ROOT_SHA_LEN,
    PSG_CERT_ROOT_ROOT_HASH_TYPE,
    PSG_CERT_ROOT_MSB_OF_PUB_KEY,
    PSG_CERT_ROOT_RESERVED,

    /* =========== PSG Certificate Entry =========== */
    PSG_CERT_MAGIC,
    PSG_CERT_LENGTH_OFFSET,
    PSG_CERT_DATA_LEN,
    PSG_CERT_SIG_LEN,
    PSG_CERT_SHA_LEN,
    PSG_CERT_RESERVED,

    /* =========== PSG AES Key =========== */
    PSG_AES_KEY_MAGIC,
    PSG_AES_KEY_CERT_DATA_LENGTH,
    PSG_AES_KEY_CERT_VERSION,
    PSG_AES_KEY_CERT_TYPE,
    PSG_AES_KEY_USER_AES_CERT_MAGIC,

    /* =========== Sigma ENC Response Message =========== */
    SIGMA_ENC_RESERVED_HEADER,
    SIGMA_ENC_MAGIC,
    SIGMA_ENC_SDM_SESSION_ID,
    SIGMA_ENC_MSG_RESP_COUNTER,
    SIGMA_ENC_PAYLOAD_LEN,
    SIGMA_ENC_INITIAL_IV,
    SIGMA_ENC_ENCRYPTED_PAYLOAD,
    SIGMA_ENC_MAC,

    /* =========== Sigma M2 Message =========== */
    SIGMA_M2_RESERVED_HEADER,
    SIGMA_M2_MAGIC,
    SIGMA_M2_SDM_SESSION_ID,
    SIGMA_M2_DEVICE_UNIQUE_ID,
    SIGMA_M2_ROM_VERSION_NUM,
    SIGMA_M2_SDM_FW_BUILD_ID,
    SIGMA_M2_SDM_FW_SECURITY_VERSION_NUM,
    SIGMA_M2_PUBLIC_EFUSE_VALUES,
    SIGMA_M2_DEVICE_DH_PUB_KEY,
    SIGMA_M2_BKPS_DH_PUB_KEY,
    SIGMA_M2_SIGNATURE,
    SIGMA_M2_MAC,

    /* =========== Certificate Response =========== */
    CERTIFICATE_PROCESS_STATUS,

    /* =========== Manifest =========== */
    MANIFEST_MAGIC,
    MANIFEST_DEVICE_UNIQUE_ID,
    MANIFEST_NUM_ENTRIES,

    /* =========== Manifest registration structure =========== */
    REG_STRUCTURE_MAGIC,
    REG_STRUCTURE_DEVICE_UNIQUE_ID,
    REG_STRUCTURE_METAL_CHECK_VALUE,
    REG_STRUCTURE_EFUSE_BLOCK,
    REG_STRUCTURE_ROM_HASH,
    REG_STRUCTURE_PUF_TYPE,
    REG_STRUCTURE_HELP_LENGTH,
    REG_STRUCTURE_HELP_DATA,

    /* =========== Attestation Manifest =========== */
    ATT_MANIFEST_MAGIC,
    ATT_FAMILY_NAME,
    ATT_LENGTH,
    ATT_DEVICE_UNIQUE_ID,
    ATT_EFUSE_BLOCK,
    ATT_INTEL_CANCELLATION,
    ATT_MANIFEST_KEY_OFFSET,
    ATT_MANIFEST_AMS_KEY_ID,

    /* =========== Rom Extension Structure =========== */
    ROM_EXT_MAGIC,
    ROM_EXT_LENGTH,
    ROM_EXT_EDI_ID,

    /* =========== Smart NIC Manifest =========== */

    NIC_MANIFEST_MAGIC,
    NIC_MANIFEST_LENGTH,
    NIC_MANIFEST_SIG_OFFSET,
    NIC_FAMILY_NAME,
    NIC_MEASUREMENT,
    NIC_METAL_CHECK_VAL,
    NIC_FIRMWARE_HASH,
    NIC_AMS_PUB_KEY,
    NIC_DEVICE_ID_PUB_KEY,
    NIC_AMS_SIG
}
