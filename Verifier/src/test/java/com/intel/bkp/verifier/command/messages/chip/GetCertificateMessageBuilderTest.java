/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.command.messages.chip;

import com.intel.bkp.verifier.model.CertificateRequestType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.ext.utils.HexConverter.toHex;
import static com.intel.bkp.verifier.model.CertificateRequestType.DEVICE_ID_ENROLLMENT;
import static com.intel.bkp.verifier.model.CertificateRequestType.FIRMWARE;
import static com.intel.bkp.verifier.model.CertificateRequestType.UDS_EFUSE_ALIAS;

class GetCertificateMessageBuilderTest {

    @Test
    void withType_DeviceIdEnrollment() {
        // when
        final byte[] certMessage = buildMessage(DEVICE_ID_ENROLLMENT);

        // then
        Assertions.assertEquals("04000000", toHex(certMessage));
    }

    @Test
    void withType_UdsEfuseAlias() {
        // when
        final byte[] certMessage = buildMessage(UDS_EFUSE_ALIAS);

        // then
        Assertions.assertEquals("10000000", toHex(certMessage));
    }

    @Test
    void withType_UdsEfuseFirmware() {
        // when
        final byte[] certMessage = buildMessage(FIRMWARE);

        // then
        Assertions.assertEquals("01000000", toHex(certMessage));
    }

    private byte[] buildMessage(CertificateRequestType requestType) {
        return new GetCertificateMessageBuilder()
            .withType(requestType)
            .build()
            .array();
    }
}
