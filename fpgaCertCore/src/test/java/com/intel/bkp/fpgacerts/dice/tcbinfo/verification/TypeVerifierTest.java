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

import static com.intel.bkp.fpgacerts.dice.tcbinfo.verification.TcbInfoTestUtil.parseTcbInfo;

class TypeVerifierTest {

    private final TypeVerifier sut = new TypeVerifier();

    @Test
    void verify_TypeValueWithMeasurementTypesChildOid_Success() {
        // given
        final String tcbInfoWithMeasurementTypesChildOid =
            "305c8009696e74656c2e636f6d840101a63f303d06096086480165030402020430020202020405060708090a0b0c0d0e0f1011121"
                + "31415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f890b6086480186f84d010f040d";
        final var tcbInfo = parseTcbInfo(tcbInfoWithMeasurementTypesChildOid);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verify_TypeValueWithMeasurementTypesMainOid_Fails() {
        // given
        final String tcbInfoWithMeasurementTypesMainOid =
            "305b8009696e74656c2e636f6d840101a63f303d06096086480165030402020430020202020405060708090a0b0c0d0e0f1011121"
                + "31415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f890a6086480186f84d010f04";
        final var tcbInfo = parseTcbInfo(tcbInfoWithMeasurementTypesMainOid);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void verify_TypeValueWithUnexpectedOid_Fails() {
        // given
        final String tcbInfoWithUnexpectedOid =
            "30568009696e74656c2e636f6d840101a63f303d06096086480165030402020430020202020405060708090a0b0c0d0e0f1011121"
                + "31415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f89050102030405";
        final var tcbInfo = parseTcbInfo(tcbInfoWithUnexpectedOid);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void verify_NoTypeField_Success() {
        // given
        final String tcbInfoWithoutTypeField =
            "304f8009696e74656c2e636f6d840101a63f303d06096086480165030402020430020202020405060708090a0b0c0d0e0f1011121"
                + "31415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        final var tcbInfo = parseTcbInfo(tcbInfoWithoutTypeField);

        // when
        final boolean result = sut.verify(tcbInfo);

        // then
        Assertions.assertTrue(result);
    }
}
