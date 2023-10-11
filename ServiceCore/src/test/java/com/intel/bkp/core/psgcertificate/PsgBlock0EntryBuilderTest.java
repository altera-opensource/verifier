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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.psgcertificate.model.PsgBlock0Entry;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.test.KeyGenUtils;
import com.intel.bkp.test.SigningUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PsgBlock0EntryBuilderTest {

    @Test
    void build_returnsSuccess() {
        // given
        KeyPair keyPair = KeyGenUtils.genEc384();
        byte[] dataToSign = new byte[1];

        // when
        assert keyPair != null;
        byte[] signedBytes =
            SigningUtils.signEcData(dataToSign, keyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA);

        PsgBlock0Entry expected = new PsgBlock0EntryBuilder()
            .signature(signedBytes, PsgSignatureCurveType.SECP384R1)
            .build();

        PsgBlock0Entry result = new PsgBlock0EntryBuilder()
            .parse(expected.array())
            .build();

        // then
        verifyCommonParsedAsserts(expected, result);
    }

    @Test
    void build_WithFirmwareActor_returnsSuccess() {
        // given
        KeyPair keyPair = KeyGenUtils.genEc384();
        byte[] dataToSign = new byte[1];

        // when
        assert keyPair != null;
        byte[] signedBytes =
            SigningUtils.signEcData(dataToSign, keyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA);

        PsgBlock0Entry expected = new PsgBlock0EntryBuilder()
            .signature(signedBytes, PsgSignatureCurveType.SECP384R1)
            .withActor(EndiannessActor.FIRMWARE)
            .build();

        PsgBlock0Entry result = new PsgBlock0EntryBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(expected.array())
            .build();

        // then
        verifyCommonParsedAsserts(expected, result);
    }

    @Test
    void predictFinalLength_Success() {
        // when
        final int length = PsgBlock0EntryBuilder.predictFinalLength();

        // then
        assertEquals(136, length);
    }

    @Test
    void parse_WithWrongMagic_ThrowsException() {
        assertThrows(ParseStructureException.class,
            () -> new PsgBlock0EntryBuilder().parse("none".getBytes())
        );
    }

    @Test
    void parse_WithLessDataInBuffer_ThrowsException() {
        // given
        final ByteBuffer buffer = ByteBuffer.allocate(3 * Integer.BYTES);
        buffer.putInt(PsgBlock0EntryBuilder.MAGIC);
        buffer.putInt(0);
        buffer.putInt(1);

        // when-then
        assertThrows(ParseStructureException.class,
            () -> new PsgBlock0EntryBuilder().parse(buffer.array())
        );
    }

    private void verifyCommonParsedAsserts(PsgBlock0Entry expected, PsgBlock0Entry actual) {
        assertArrayEquals(expected.getDataLength(), actual.getDataLength());
        assertArrayEquals(expected.getSignatureLength(), actual.getSignatureLength());
        assertArrayEquals(expected.getShaLength(), actual.getShaLength());
        assertArrayEquals(expected.getLengthOffset(), actual.getLengthOffset());
        assertArrayEquals(expected.getMagic(), actual.getMagic());
        assertArrayEquals(expected.getReserved(), actual.getReserved());
        assertArrayEquals(expected.getPsgSignature(), actual.getPsgSignature());
    }

}
