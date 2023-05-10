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

package com.intel.bkp.fpgacerts.dice.tcbinfo;

import org.bouncycastle.asn1.ASN1Primitive;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static com.intel.bkp.utils.HexConverter.fromHex;

class TcbInfoParserTest {

    // Detailed description of how to generate such TCB INFO data is in TcbInfoTestUtil.java
    private static final String MULTI_FWIDS_TCB_INFO =
        "3081a08009696e74656c2e636f6d81064167696c657883011a840100850100a67e303d06096086480165030402020430ff010203"
            + "0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303d060960"
            + "86480165030402010430000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526"
            + "2728292a2b2c2d2e2f87020640";

    @Test
    void parse_WithMultipleFwIdsInTcbInfo_Throws() throws IOException {
        // given
        final String expectedMessage = "FwIds field contains multiple FwId values: ";
        final ASN1Primitive asn1Encodable = ASN1Primitive.fromByteArray(fromHex(MULTI_FWIDS_TCB_INFO));

        // when-then
        final IllegalArgumentException exception =
            Assertions.assertThrows(IllegalArgumentException.class, () -> TcbInfoParser.parseTcbInfo(asn1Encodable));
        Assertions.assertTrue(exception.getMessage().contains(expectedMessage));
    }

}
