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

package com.intel.bkp.command.logger;

public enum CommandLoggerValues {

    PSGSIGMA_TEARDOWN_MESSAGE,
    PSGSIGMA_TEARDOWN_RESPONSE,
    GET_CHIPID_MESSAGE,
    GET_CHIPID_RESPONSE,
    PSGSIGMA_M1,
    PSGSIGMA_M2,
    PSGSIGMA_M3_MESSAGE,
    PSGSIGMA_M3_RESPONSE,
    PSGSIGMA_ENC_MESSAGE,
    PSGSIGMA_ENC_RESPONSE,
    PSGSIGMA_ENC_PAYLOAD_RESPONSE,
    VOLATILE_AES_ERASE_MESSAGE,
    GET_IDCODE_MESSAGE,
    GET_IDCODE_RESPONSE,
    GET_DEVICE_IDENTITY_MESSAGE,
    GET_DEVICE_IDENTITY_RESPONSE,
    CERTIFICATE_MESSAGE,
    CERTIFICATE_RESPONSE,
    WRAPPED_AES_KEY_DATA,
    GET_ATTESTATION_CERTIFICATE_MESSAGE,
    GET_ATTESTATION_CERTIFICATE_RESPONSE,
    CREATE_ATTESTATION_SUBKEY_MESSAGE,
    GET_MEASUREMENT_MESSAGE
}
