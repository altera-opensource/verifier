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
import com.intel.bkp.core.psgcertificate.exceptions.PsgPublicKeyBuilderException;
import com.intel.bkp.core.psgcertificate.model.PsgCancellation;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKey;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.core.utils.ModifyBitsBuilder;
import com.intel.bkp.crypto.curve.CurvePoint;
import com.intel.bkp.test.KeyGenUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.concurrent.ThreadLocalRandom;

import static com.intel.bkp.core.psgcertificate.PsgPublicKeyBuilder.PSG_SHA384_FORMAT_LEN;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PsgPublicKeyBuilderTest {

    private static final String EMPTY_PSG_SAMPLE = "000000000000000000000000000000000000000000000000000000000000000000"
        + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        + "0000000000000000000000000000000000000000000000000000000000000000000";

    @Test
    void builder_WithEcPubKey_Success() {
        // given
        final KeyPair keyPair = KeyGenUtils.genEc384();

        // when
        final PsgPublicKeyBuilder builder = prepareBuilder(keyPair);

        // then
        assertNotNull(builder);
        assertEquals(PSG_SHA384_FORMAT_LEN, builder.totalLen());
    }

    @Test
    void builder_WithEncodedECPubKey_Success() throws PsgPublicKeyBuilderException {
        // given
        final KeyPair keyPair = KeyGenUtils.genEc384();

        // when
        final PsgPublicKeyBuilder builder = prepareBuilder(keyPair.getPublic().getEncoded());

        // then
        assertNotNull(builder);
        assertEquals(PSG_SHA384_FORMAT_LEN, builder.totalLen());
    }

    @Test
    void builder_WithEncodedRSAPubKey_ThrowsException() {
        // given
        final KeyPair keyPair = KeyGenUtils.genRsa3072();

        // when-then
        assertThrows(PsgPublicKeyBuilderException.class, () ->
            prepareBuilder(keyPair.getPublic().getEncoded()));
    }

    @Test
    void builder_WithEncodedECPubKeyXY_Success() {
        // when
        final PsgPublicKeyBuilder builder = prepareBuilderXY(getPubKeyXY());

        // then
        assertNotNull(builder);
        assertEquals(PSG_SHA384_FORMAT_LEN, builder.totalLen());
    }

    @Test
    void build_WithEcPubKey_Success() {
        // given
        final KeyPair keyPair = KeyGenUtils.genEc384();
        final PsgPublicKeyBuilder builder = prepareBuilder(keyPair);

        // when
        final PsgPublicKey psgPublicKey = builder.build();

        // then
        assertNotNull(psgPublicKey);
    }

    @Test
    void parse_WithEcPubKey_WithHexData_Success() {
        // given
        final KeyPair keyPair = KeyGenUtils.genEc384();
        final byte[] preparedData = prepareBuilder(keyPair).build().array();

        // when
        final PsgPublicKeyBuilder publicKeyBuilder = new PsgPublicKeyBuilder()
            .parse(toHex(preparedData));

        // then
        assertNotNull(publicKeyBuilder);
    }

    @Test
    void parse_WithEcPubKey_WithByteArrayData_Success() {
        // given
        final KeyPair keyPair = KeyGenUtils.genEc384();
        final byte[] preparedData = prepareBuilder(keyPair).build().array();

        // when
        final PsgPublicKeyBuilder publicKeyBuilder = new PsgPublicKeyBuilder()
            .parse(preparedData);

        // then
        assertNotNull(publicKeyBuilder);
    }

    @Test
    void build_WithEmptyBuilder_Success() {
        // given
        final var publicKeyBuilder = new PsgPublicKeyBuilder()
            .curvePoint(CurvePoint.from(new byte[]{0}, new byte[]{0}, PsgCurveType.SECP384R1.getCurveSpec()))
            .withActor(EndiannessActor.FIRMWARE);

        // when
        final String result = publicKeyBuilder.build().toHex();

        // then
        assertEquals("6006705800000000000000004866325400000000FFFFFFFF0000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "00000000000000000000000000000000000000000000000000000000000000", result);
    }

    @Test
    void parse_WithEmptyPubKey_Success() {
        // when
        final PsgPublicKeyBuilder publicKeyBuilder = new PsgPublicKeyBuilder()
            .parse(EMPTY_PSG_SAMPLE);

        // then
        assertNotNull(publicKeyBuilder);
        assertEquals(PsgPublicKeyMagic.EMPTY, publicKeyBuilder.getMagic());
    }

    @Test
    void build_WithEmptyPubKey_Success() {
        // given
        final var publicKeyBuilder = new PsgPublicKeyBuilder()
            .empty()
            .withActor(EndiannessActor.FIRMWARE);

        // when
        final String result = publicKeyBuilder.build().toHex();

        // then
        assertEquals(EMPTY_PSG_SAMPLE, result);
    }

    private PsgPublicKeyBuilder prepareBuilder(KeyPair keyPair) {
        return new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.MANIFEST_MAGIC)
            .withActor(EndiannessActor.SERVICE)
            .permissions(ModifyBitsBuilder.fromNone().build())
            .cancellation(PsgCancellation.CANCELLATION_ID_MIN)
            .publicKey(keyPair.getPublic(), PsgCurveType.SECP384R1);
    }

    private PsgPublicKeyBuilder prepareBuilder(byte[] encodedPublicKey) throws PsgPublicKeyBuilderException {
        return new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.MANIFEST_MAGIC)
            .withActor(EndiannessActor.SERVICE)
            .permissions(ModifyBitsBuilder.fromNone().build())
            .cancellation(PsgCancellation.CANCELLATION_ID_MIN)
            .publicKey(encodedPublicKey, PsgCurveType.SECP384R1);
    }

    private PsgPublicKeyBuilder prepareBuilderXY(byte[] publicKeyXY) {
        return new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.MANIFEST_MAGIC)
            .withActor(EndiannessActor.SERVICE)
            .permissions(ModifyBitsBuilder.fromNone().build())
            .cancellation(PsgCancellation.CANCELLATION_ID_MIN)
            .publicKeyPointXY(publicKeyXY, PsgCurveType.SECP384R1);
    }

    private byte[] getPubKeyXY() {
        PsgCurveType curveType = PsgCurveType.SECP384R1;
        byte[] pubKeyX = new byte[curveType.getCurveSpec().getSize()];
        byte[] pubKeyY = new byte[curveType.getCurveSpec().getSize()];
        ThreadLocalRandom.current().nextBytes(pubKeyX);
        ThreadLocalRandom.current().nextBytes(pubKeyY);
        return ByteBuffer.allocate(pubKeyX.length + pubKeyY.length).put(pubKeyX).put(pubKeyY).array();
    }

}
