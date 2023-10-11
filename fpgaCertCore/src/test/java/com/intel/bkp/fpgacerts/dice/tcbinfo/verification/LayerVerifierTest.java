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

class LayerVerifierTest {

    private final LayerVerifier sut = new LayerVerifier();

    @Test
    void verify_ZeroLayerValue_Success() {
        // given
        final String tcbInfoWithLayerValueZero =
            "305D8009696E74656C2E636F6D81064167696C6578830105840100850100A63F303D06096086480165030402020430FF0102030405"
                + "060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F";
        final var tcbInfo = parseTcbInfo(tcbInfoWithLayerValueZero);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        assertTrue(result);
    }

    @Test
    void verify_PositiveLayerValue_Success() {
        // given
        final String tcbInfoWithLayerValueFifteen =
            "305D8009696E74656C2E636F6D81064167696C657883010584010F850100A63F303D06096086480165030402020430FF0102030405"
                + "060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F";
        final var tcbInfo = parseTcbInfo(tcbInfoWithLayerValueFifteen);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        assertTrue(result);
    }

    @Test
    void verify_NegativeLayerValue_Fails() {
        // given
        final String tcbInfoWithLayerValueTwo =
            "30618009696e74656c2e636f6d81064167696c657883011a8401fd850100a63f303d0609608648016503040202043002020202040"
                + "5060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f87020640";
        final var tcbInfo = parseTcbInfo(tcbInfoWithLayerValueTwo);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        assertFalse(result);
    }

    @Test
    void verify_NoLayerField_Fails() {
        // given
        final String tcbInfoWithoutLayerField =
            "305A8009696E74656C2E636F6D81064167696C6578830105850100A63F303D06096086480165030402020430FF010203040506070"
                + "8090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F";
        final var tcbInfo = parseTcbInfo(tcbInfoWithoutLayerField);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        assertFalse(result);
    }

}
