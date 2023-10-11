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

class SvnVerifierTest {

    private final SvnVerifier sut = new SvnVerifier();

    @Test
    void verify_MinSvnValue_Success() {
        // given
        final String tcbInfoWithMinSvnValue =
            "30618009696e74656c2e636f6d81064167696c6578830100840101850100a63f303d0609608648016503040202043002020202040"
                + "5060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f87020640";
        final var tcbInfo = parseTcbInfo(tcbInfoWithMinSvnValue);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        assertTrue(result);
    }

    @Test
    void verify_MaxSvnValue_Success() {
        // given
        final String tcbInfoWithMaxSvnValue =
            "30618009696e74656c2e636f6d81064167696c6578830111840101850100a63f303d0609608648016503040202043002020202040"
                + "5060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f87020640";
        final var tcbInfo = parseTcbInfo(tcbInfoWithMaxSvnValue);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        assertTrue(result);
    }

    @Test
    void verify_SvnValueInRange_Success() {
        // given
        final String tcbInfoWithSvnValueInRange =
            "30618009696e74656c2e636f6d81064167696c657883011f840101850100a63f303d0609608648016503040202043002020202040"
                + "5060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f87020640";
        final var tcbInfo = parseTcbInfo(tcbInfoWithSvnValueInRange);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        assertTrue(result);
    }

    @Test
    void verify_SvnValueOutOfRange_Fails() {
        // given
        final String tcbInfoWithSvnValueOutOfRange =
            "30618009696e74656c2e636f6d81064167696c6578830120840101850100a63f303d0609608648016503040202043002020202040"
                + "5060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f87020640";
        final var tcbInfo = parseTcbInfo(tcbInfoWithSvnValueOutOfRange);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        assertFalse(result);
    }

    @Test
    void verify_NoSvnValue_Success() {
        // given
        final String tcbInfoWithoutSvnValue =
            "305e8009696e74656c2e636f6d81064167696c6578840101850100a63f303d0609608648016503040202043002020202040506070"
                + "8090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f87020640";
        final var tcbInfo = parseTcbInfo(tcbInfoWithoutSvnValue);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        assertTrue(result);
    }

}
