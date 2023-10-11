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

package com.intel.bkp.command.messages.common;

import com.intel.bkp.test.RandomUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CertificateBuilderTest {

    private static final int DATA_LEN = 416;

    @Test
    public void build_ReturnValidObject() {
        // given
        final byte[] expectedData = RandomUtils.generateRandomBytes(DATA_LEN);
        final Certificate msg = new CertificateBuilder(expectedData)
            .build();

        // when
        final byte[] result = msg.array();
        Certificate resultMessage = new CertificateBuilder().parse(result).build();

        // then
        assertNotNull(result);
        assertNotNull(resultMessage);

        assertArrayEquals(expectedData, msg.getUserAesRootKeyCertificate());
        assertArrayEquals(msg.getUserAesRootKeyCertificate(), resultMessage.getUserAesRootKeyCertificate());
    }

    @Test
    public void hex_ReturnsValidHexWithHash() {
        // given
        byte[] certificate = new byte[128];
        String sha384Of128ZeroBytes =
            "F809B88323411F24A6F152E5E9D9D1B5466B77E0F3C7550F8B242C31B6E7B99BCB45BDECB6124BC23283DB3B9FC4F5B3";
        String expectedAssetHash =
            "F809B88323411F24A6F152E5...<hidden SHA384 bytes>...B6124BC23283DB3B9FC4F5B3";

        Certificate msg = new CertificateBuilder(certificate)
            .build();

        // when
        String result = msg.hex();

        // then
        assertTrue(result.contains(expectedAssetHash));
        assertFalse(result.contains(sha384Of128ZeroBytes));
    }

}
