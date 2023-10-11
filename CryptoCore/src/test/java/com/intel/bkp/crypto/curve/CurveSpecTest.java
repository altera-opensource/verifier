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

package com.intel.bkp.crypto.curve;

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.CurveNameMappingException;
import com.intel.bkp.test.KeyGenUtils;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CurveSpecTest {

    @Test
    void fromBcCurveTypeEc_WithExisting_Success() {
        // when
        final CurveSpec actual = CurveSpec.fromBcCurveTypeEc(CryptoConstants.EC_CURVE_SPEC_521);

        // then
        assertEquals(CurveSpec.C521, actual);
    }

    @Test
    void fromBcCurveTypeEc_WithNotExisting_ThrowsException() {
        // when-then
        assertThrows(IllegalArgumentException.class, () -> CurveSpec.fromBcCurveTypeEc("abc"));
    }

    @Test
    void getCurveSpec_Success() {
        // given
        final KeyPair ec384Keys = KeyGenUtils.genEc384();

        // when
        final CurveSpec curveSpec = CurveSpec.getCurveSpec(ec384Keys.getPublic());

        // then
        assertEquals(CurveSpec.C384, curveSpec);
    }

    @Test
    void getCurveSpec_WithRsaKey_ThrowsException() {
        // given
        final KeyPair rsaKeys = KeyGenUtils.genRsa3072();

        // when-then
        assertThrows(CurveNameMappingException.class,
            () -> CurveSpec.getCurveSpec(rsaKeys.getPublic()));
    }
}
