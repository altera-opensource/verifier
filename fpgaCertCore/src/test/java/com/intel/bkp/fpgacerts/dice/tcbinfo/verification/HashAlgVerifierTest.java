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

package com.intel.bkp.fpgacerts.dice.tcbinfo.verification;

import org.junit.jupiter.api.Test;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.verification.TcbInfoTestUtil.parseTcbInfo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HashAlgVerifierTest {

    private final HashAlgVerifier sut = new HashAlgVerifier();

    @Test
    void verify_ValidHashAlgValue_Success() {
        // given
        final String tcbInfoWithSha384HashAlg =
            "305D8009696E74656C2E636F6D81064167696C6578830100840101850100A63F303D06096086480165030402020430309326BB3193"
                + "26BB329326BB339326BB349326BB359326BB369326BB379326BB389326BB399326BB3A9326BB3B9326BB";
        final var tcbInfo = parseTcbInfo(tcbInfoWithSha384HashAlg);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        assertTrue(result);
    }

    @Test
    void verify_InvalidHashAlgValue_Fails() {
        // given
        final String tcbInfoWithSha256HashAlg =
            "305D8009696E74656C2E636F6D81064167696C6578830105840100850100A63F303D06096086480165030402010430FF0102030405"
                + "060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F";
        final var tcbInfo = parseTcbInfo(tcbInfoWithSha256HashAlg);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        assertFalse(result);
    }

    @Test
    void verify_NoFwIdField_Success() {
        // given
        final String tcbInfoWithoutFwIdField =
            "301C8009696E74656C2E636F6D81064167696C6578830105840100850100";
        final var tcbInfo = parseTcbInfo(tcbInfoWithoutFwIdField);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        assertTrue(result);
    }
}
