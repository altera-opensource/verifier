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

package com.intel.bkp.verifier.jna.model;

public class SpdmConstants {

    // Values taken from libspdm library
    public static final int LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE = 20064;
    public static final long LIBSPDM_STATUS_SUCCESS = 0x0L;
    public static final long LIBSPDM_STATUS_SPDM_VERIFIER_EXCEPTION = 0x00000000800100FEL;  // custom error code
    public static final long LIBSPDM_STATUS_SPDM_NOT_SUPPORTED = 0x00000000800100FDL; // custom error code
    public static final int SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE = 0x00000001;
    public static final int SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED = 0x00000002;
    public static final int SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF = 0x00000001;
    public static final int SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 = 0x00000080;
    public static final int SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 = 0x00000002;
    public static final int MAX_SLOT_COUNT = 8;
    public static final int DEFAULT_SLOT_ID = 0x0;
    public static final int DEFAULT_CT_EXPONENT = 0x0E;
}
