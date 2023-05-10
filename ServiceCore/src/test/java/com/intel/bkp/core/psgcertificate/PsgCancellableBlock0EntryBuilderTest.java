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

import com.intel.bkp.core.TestUtil;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgBlock0EntryException;
import com.intel.bkp.core.psgcertificate.model.PsgCancellableBlock0Entry;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.KeyPair;

import static com.intel.bkp.core.TestUtil.genEcKeys;

class PsgCancellableBlock0EntryBuilderTest {

    @Test
    void build_returnsSuccess() throws PsgBlock0EntryException {
        // given
        final PsgCancellableBlock0Entry expected = prepareEntry(EndiannessActor.SERVICE);

        // when
        PsgCancellableBlock0Entry result = new PsgCancellableBlock0EntryBuilder()
            .parse(expected.array())
            .build();

        // then
        verifyCommonParsedAsserts(expected, result);
    }

    @Test
    void build_WithFirmwareActor_returnsSuccess() throws PsgBlock0EntryException {
        // given
        final PsgCancellableBlock0Entry expected = prepareEntry(EndiannessActor.FIRMWARE);

        // when
        PsgCancellableBlock0Entry result = new PsgCancellableBlock0EntryBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(expected.array())
            .build();

        // then
        verifyCommonParsedAsserts(expected, result);
    }

    @Test
    void parse_WithWrongMagic_ThrowsException() {
        // when-then
        Assertions.assertThrows(ParseStructureException.class,
            () -> new PsgCancellableBlock0EntryBuilder().parse("none".getBytes())
        );
    }

    @Test
    void parse_WithWrongMetaDataMagic_ThrowsException() {
        // given
        final PsgCancellableBlock0Entry expected = prepareEntry(EndiannessActor.SERVICE);
        expected.setBlock0MetaMagic(ByteSwap.getSwappedArray(0x99999999, ByteSwapOrder.CONVERT));

        // when-then
        Assertions.assertThrows(ParseStructureException.class,
            () -> new PsgCancellableBlock0EntryBuilder().parse(expected.array())
        );
    }

    @Test
    void parse_WithLessDataInBuffer_ThrowsException() {
        // given
        final ByteBuffer buffer = ByteBuffer.allocate(3 * Integer.BYTES);
        buffer.putInt(PsgCancellableBlock0EntryBuilder.MAGIC);
        buffer.putInt(0);
        buffer.putInt(1);

        // when-then
        Assertions.assertThrows(ParseStructureException.class,
            () -> new PsgCancellableBlock0EntryBuilder().parse(buffer.array())
        );
    }

    private void verifyCommonParsedAsserts(PsgCancellableBlock0Entry expected, PsgCancellableBlock0Entry actual) {
        Assertions.assertArrayEquals(expected.getDataLength(), actual.getDataLength());
        Assertions.assertArrayEquals(expected.getSignatureLength(), actual.getSignatureLength());
        Assertions.assertArrayEquals(expected.getShaLength(), actual.getShaLength());
        Assertions.assertArrayEquals(expected.getLengthOffset(), actual.getLengthOffset());
        Assertions.assertArrayEquals(expected.getMagic(), actual.getMagic());
        Assertions.assertArrayEquals(expected.getReserved(), actual.getReserved());
        Assertions.assertArrayEquals(expected.getBlock0MetaMagic(), actual.getBlock0MetaMagic());
        Assertions.assertArrayEquals(expected.getCancellationId(), actual.getCancellationId());
        Assertions.assertArrayEquals(expected.getPsgSignature(), actual.getPsgSignature());
    }

    private static PsgCancellableBlock0Entry prepareEntry(EndiannessActor endiannessActor) {
        KeyPair keyPair = genEcKeys(null);
        byte[] dataToSign = new byte[1];
        assert keyPair != null;
        final byte[] signedData = TestUtil.signEcData(dataToSign, keyPair.getPrivate(),
            CryptoConstants.SHA384_WITH_ECDSA);
        return new PsgCancellableBlock0EntryBuilder()
            .signature(signedData, PsgSignatureCurveType.SECP384R1)
            .withActor(endiannessActor)
            .build();
    }
}
