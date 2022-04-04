/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2022 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class PsgSignatureHelperTest {

    @Test
    void verifySignatureMagic_Success() throws Exception {
        // when
        PsgSignatureHelper.verifySignatureMagic(PsgSignatureHelper.SIGNATURE_MAGIC);
    }

    @Test
    void verifySignatureMagic_InvalidMagic_Throws() {
        Assertions.assertThrows(PsgInvalidSignatureException.class, () -> PsgSignatureHelper.verifySignatureMagic(0));
    }

    @Test
    void getTotalSignatureSize_ForSecp384_Returns_Correct() {
        // when
        int result = PsgSignatureHelper.getTotalSignatureSize(PsgSignatureCurveType.SECP384R1);

        // then
        Assertions.assertEquals(112, result);
    }

    @Test
    void getTotalSignatureSize_ForSecp256_Returns_Correct() {
        // when
        int result = PsgSignatureHelper.getTotalSignatureSize(PsgSignatureCurveType.SECP256R1);

        // then
        Assertions.assertEquals(80, result);
    }

    @Test
    void parseSignatureType_Success() throws PsgInvalidSignatureException {
        // given
        final PsgSignatureCurveType expectedType = PsgSignatureCurveType.SECP384R1;

        // when
        final PsgSignatureCurveType actual = PsgSignatureHelper.parseSignatureType(expectedType.getMagic());

        // then
        Assertions.assertEquals(expectedType, actual);
    }

    @Test
    void parseSignatureType_WithWrongHashMagic_ThrowsException() {
        Assertions.assertThrows(PsgInvalidSignatureException.class,
            () -> PsgSignatureHelper.parseSignatureType(1555)
        );
    }
}
