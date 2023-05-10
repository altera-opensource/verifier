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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.verification.TcbInfoTestUtil.parseTcbInfo;

@ExtendWith(MockitoExtension.class)
class FlagsVerifierTest {

    @Test
    void verify_NoFlagsField_Success() {
        // given
        final String tcbInfoWithoutFlagField =
            "305D8009696E74656C2E636F6D81064167696C6578830100840101850100A63F303D06096086480165030402020430309326BB3193"
                + "26BB329326BB339326BB349326BB359326BB369326BB379326BB389326BB399326BB3A9326BB3B9326BB";
        final var tcbInfo = parseTcbInfo(tcbInfoWithoutFlagField);

        // when
        final boolean result = new FlagsVerifier(false).verify(tcbInfo);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verify_FlagsAllZeros_Success() {
        // given
        final String tcbInfoWithAllFlagsNotSet =
            "30608009696E74656C2E636F6D81064167696C6578830100840101850100A63F303D06096086480165030402020430309326BB3193"
                + "26BB329326BB339326BB349326BB359326BB369326BB379326BB389326BB399326BB3A9326BB3B9326BB870100";
        final var tcbInfo = parseTcbInfo(tcbInfoWithAllFlagsNotSet);

        // when
        final boolean result = new FlagsVerifier(false).verify(tcbInfo);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verify_FlagsNotAllZeros_NotCmfHash_Success() {
        // given
        final String tcbInfoWithAFlagSet =
            "30618009696E74656C2E636F6D81064167696C6578830100840100850100A63F303D06096086480165030402020430309326BB3193"
                + "26BB329326BB339326BB349326BB359326BB369326BB379326BB389326BB399326BB3A9326BB3B9326BB87020640";
        final var tcbInfo = parseTcbInfo(tcbInfoWithAFlagSet);

        // when
        final boolean result = new FlagsVerifier(false).verify(tcbInfo);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verify_FlagsNotAllZeros_CmfHash_Fails() {
        // given
        final String tcbInfoWithAFlagSet =
            "30618009696E74656C2E636F6D81064167696C6578830100840101850100A63F303D06096086480165030402020430309326BB3193"
                + "26BB329326BB339326BB349326BB359326BB369326BB379326BB389326BB399326BB3A9326BB3B9326BB87020640";
        final var tcbInfo = parseTcbInfo(tcbInfoWithAFlagSet);

        // when
        final boolean result = new FlagsVerifier(false).verify(tcbInfo);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void verify_FlagsNotAllZeros_CmfHash_TestModeSecrets_Success() {
        // given
        final String tcbInfoWithAFlagSet =
            "30618009696E74656C2E636F6D81064167696C6578830100840101850100A63F303D06096086480165030402020430309326BB3193"
                + "26BB329326BB339326BB349326BB359326BB369326BB379326BB389326BB399326BB3A9326BB3B9326BB87020640";
        final var tcbInfo = parseTcbInfo(tcbInfoWithAFlagSet);

        // when
        final boolean result = new FlagsVerifier(true).verify(tcbInfo);

        // then
        Assertions.assertTrue(result);
    }
}
