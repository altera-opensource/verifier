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

import com.intel.bkp.core.TestUtil;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.core.psgcertificate.model.PsgSignature;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureMagic;
import com.intel.bkp.crypto.constants.CryptoConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;

class PsgSignatureBuilderTest {

    private final String PSG_EMPTY_SIGNATURE_FIRMWARE = "20158874000000000000000020885430000000000000000000000000000000"
        + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        + "000000000000000000000000000000000000000000000000000000";

    @Test
    void build_WithSignature_Success() {
        // given
        KeyPair keyPair = TestUtil.genEcKeys();
        byte[] testData = "TestDataToSignAndVerify".getBytes();
        byte[] signed = TestUtil.signEcData(testData, keyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA);

        // when
        final PsgSignature signature = new PsgSignatureBuilder()
            .signature(signed, PsgSignatureCurveType.SECP384R1)
            .build();

        // then
        Assertions.assertEquals(toHex(PsgSignatureMagic.STANDARD.getValue()),
            toHex(signature.getSignatureMagic()));
        Assertions.assertEquals(toHex(PsgSignatureCurveType.SECP384R1.getMagic()),
            toHex(signature.getSignatureHashMagic()));
        Assertions.assertNotNull(signature.getSignatureR());
        Assertions.assertNotNull(signature.getSignatureS());
    }

    @Test
    void build_WithEmptySignature_Success() {
        // when
        final byte[] signature = PsgSignatureBuilder.empty(PsgSignatureCurveType.SECP384R1)
            .withActor(EndiannessActor.FIRMWARE)
            .build()
            .array();

        // then
        Assertions.assertEquals(PSG_EMPTY_SIGNATURE_FIRMWARE, toHex(signature));
    }

    @Test
    void parse_WithEmptySignature_Success() throws PsgInvalidSignatureException {
        // when
        final PsgSignatureBuilder builder = new PsgSignatureBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(fromHex(PSG_EMPTY_SIGNATURE_FIRMWARE));

        // then
        Assertions.assertEquals(PsgSignatureMagic.STANDARD, builder.getMagic());
        Assertions.assertEquals("0".repeat(96), builder.getCurvePoint().getHexPointA());
        Assertions.assertEquals("0".repeat(96), builder.getCurvePoint().getHexPointB());
        Assertions.assertEquals(PsgSignatureCurveType.SECP384R1, PsgSignatureCurveType.fromCurveSpec(
            builder.getCurvePoint().getCurveSpec()
        ));
    }

    @Test
    void parse_WithEmptySignature_WithNotValidActor_ThrowsException() {
        // when-then
        Assertions.assertThrows(PsgInvalidSignatureException.class,
            () -> new PsgSignatureBuilder().parse(fromHex(PSG_EMPTY_SIGNATURE_FIRMWARE)));
    }

    @Test
    void getTotalSignatureSize_WithSignature_Success() {
        // given
        KeyPair keyPair = TestUtil.genEcKeys();
        byte[] testData = "TestDataToSignAndVerify".getBytes();
        byte[] signed = TestUtil.signEcData(testData, keyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA);
        final int expected = PsgSignatureBuilder.getTotalSignatureSize(PsgSignatureCurveType.SECP384R1);

        // when
        final int sigSize = new PsgSignatureBuilder()
            .signature(signed, PsgSignatureCurveType.SECP384R1)
            .getTotalSignatureSize();

        // then
        Assertions.assertEquals(expected, sigSize);
    }

    @Test
    void getTotalSignatureSize_ForSecp384_Returns_Correct() {
        // when
        int result = PsgSignatureBuilder.getTotalSignatureSize(PsgSignatureCurveType.SECP384R1);

        // then
        Assertions.assertEquals(112, result);
    }

    @Test
    void getTotalSignatureSize_ForSecp256_Returns_Correct() {
        // when
        int result = PsgSignatureBuilder.getTotalSignatureSize(PsgSignatureCurveType.SECP256R1);

        // then
        Assertions.assertEquals(80, result);
    }
}
