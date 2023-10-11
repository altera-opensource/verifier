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

package com.intel.bkp.crypto.asn1;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static com.intel.bkp.crypto.asn1.Asn1ParsingUtils.convertToDerSignature;
import static com.intel.bkp.crypto.asn1.Asn1ParsingUtils.extractR;
import static com.intel.bkp.crypto.asn1.Asn1ParsingUtils.extractS;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Asn1ParsingUtilsTest {

    private static final String EXPECTED_SIGNATURE =
        "3066023100D1E2CC1B5A1F9AAE856240B8AF63C43A454BA6738CCF97ED69866E2358DA35B1125D692F252121D4AFD9"
            + "39B761E78636023100D27538C2E17C0AAD1A1F793599ADCA08A9CCB5D14729FA4F319DE2E51EA9BCA5C9DFEC"
            + "D303971B77820F2F3F96C35FCC";

    private static final String EXPECTED_R =
        "00D1E2CC1B5A1F9AAE856240B8AF63C43A454BA6738CCF97ED69866E2358DA35B1125D692F252121D4AFD939B761E78636";
    private static final String EXPECTED_S =
        "00D27538C2E17C0AAD1A1F793599ADCA08A9CCB5D14729FA4F319DE2E51EA9BCA5C9DFECD303971B77820F2F3F96C35FCC";

    @Test
    void extractR_WithValidSignature_Success() {
        // when
        final byte[] actual = extractR(fromHex(EXPECTED_SIGNATURE));

        // then
        assertEquals(EXPECTED_R, toHex(actual));
    }

    @Test
    void extractS_WithValidSignature_Success() {
        // when
        final byte[] actual = extractS(fromHex(EXPECTED_SIGNATURE));

        // then
        assertEquals(EXPECTED_S, toHex(actual));
    }

    @Test
    void extractR_WithRNotDerFormat_ThrowsException() {
        // given
        final byte[] signature = fromHex(EXPECTED_R + EXPECTED_S);

        // when-then
        assertThrows(IllegalArgumentException.class, () -> extractR(signature));
    }

    @Test
    void extractS_WithSNotDerFormat_ThrowsException() {
        // given
        final byte[] signature = fromHex(EXPECTED_R + EXPECTED_S);

        // when-then
        assertThrows(IllegalArgumentException.class, () -> extractS(signature));
    }

    @Test
    void convertDER_Success() throws IOException {
        // when
        final byte[] valid = convertToDerSignature(fromHex(EXPECTED_R), fromHex(EXPECTED_S));

        // then
        assertEquals(EXPECTED_SIGNATURE, toHex(valid));
    }
}
