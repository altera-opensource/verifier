/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2023 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.endianness;

import com.intel.bkp.core.endianness.IStructureField;

public enum StructureField implements IStructureField {
    /* =========== CreateAttestationSubKey Response =========== */
    SUBKEY_RESERVED_HEADER,
    SUBKEY_MAGIC,
    SUBKEY_SDM_SESSION_ID,
    SUBKEY_DEVICE_UNIQUE_ID,
    SUBKEY_ROM_VERSION_NUM,
    SUBKEY_SDM_FW_BUILD_ID,
    SUBKEY_SDM_FW_SECURITY_VERSION_NUM,
    SUBKEY_RESERVED,
    SUBKEY_PUBLIC_EFUSE_VALUES,
    SUBKEY_DEVICE_DH_PUB_KEY,
    SUBKEY_VERIFIER_DH_PUB_KEY,
    SUBKEY_CONTEXT,
    SUBKEY_COUNTER,
    SUBKEY_MAC,

    /* =========== GetMeasurement Response =========== */
    GET_MEASUREMENT_MAGIC,
    GET_MEASUREMENT_SDM_SESSION_ID,
    GET_MEASUREMENT_DEVICE_UNIQUE_ID,
    GET_MEASUREMENT_ROM_VERSION_NUM,
    GET_MEASUREMENT_SDM_FW_BUILD_ID,
    GET_MEASUREMENT_SDM_FW_SECURITY_VERSION_NUM,
    GET_MEASUREMENT_PUBLIC_EFUSE_VALUES,
    GET_MEASUREMENT_DEVICE_DH_PUB_KEY,
    GET_MEASUREMENT_VERIFIER_DH_PUB_KEY,
    GET_MEASUREMENT_CMF_DESCRIPTOR_HASH,
    GET_MEASUREMENT_RECORD_LEN,
    GET_MEASUREMENT_MAC,

    /* =========== SpdmMeasurementBlock =========== */
    SPDM_DMTF_MEASUREMENT_HEADER_LEN


}
