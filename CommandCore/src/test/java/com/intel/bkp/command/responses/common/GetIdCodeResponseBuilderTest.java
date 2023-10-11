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

package com.intel.bkp.command.responses.common;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

class GetIdCodeResponseBuilderTest {

    private static final byte[] REAL_RESPONSE_FROM_FM7 = fromHex("DDD04163");

    private GetIdCodeResponseBuilder sut;

    @BeforeEach
    void setUp() {
        sut = new GetIdCodeResponseBuilder();
    }

    @Test
    void parse_Success() {
        // given
        final byte expectedManufacturer = 0x6;
        final byte expectedFamilyId = 0x34;
        final String expectedDeviceSpecificNumber = "1D0DD";

        // when
        final GetIdCodeResponse result = sut.parse(REAL_RESPONSE_FROM_FM7).build();

        // then
        assertEquals(expectedManufacturer, result.getManufacturer());
        assertEquals(expectedFamilyId, result.getFamilyId());
        assertEquals(expectedDeviceSpecificNumber, result.getDeviceSpecificNumber());
    }

    @Test
    void toString_Success() {
        // given
        final String expectedToStringResult = "GetIdCodeResponse { idCode = 0xddd04163, manufacturer = 0x06"
            + ", familyId = 0x34 (52), deviceSpecificNumber = 0x1d0dd }";

        // when
        final GetIdCodeResponse result = sut.parse(REAL_RESPONSE_FROM_FM7).build();

        // then
        assertEquals(expectedToStringResult, result.toString());
    }

}
