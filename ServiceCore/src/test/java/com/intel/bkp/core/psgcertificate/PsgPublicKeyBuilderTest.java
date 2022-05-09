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
import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgPublicKeyBuilderException;
import com.intel.bkp.core.psgcertificate.model.PsgCancellation;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKey;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.core.utils.ModifyBitsBuilder;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.Random;

import static com.intel.bkp.utils.HexConverter.toHex;

class PsgPublicKeyBuilderTest {

    private static final int PSG_SHA384_FORMAT_LEN = 120;

    @Test
    void builder_WithEcPubKey_Success() {
        // given
        final KeyPair keyPair = TestUtil.genEcKeys();

        // when
        final PsgPublicKeyBuilder builder = prepareBuilder(keyPair);

        // then
        Assertions.assertNotNull(builder);
        Assertions.assertEquals(PSG_SHA384_FORMAT_LEN, builder.totalLen());
    }

    @Test
    void builder_WithEncodedECPubKey_Success() throws PsgPublicKeyBuilderException {
        // given
        final KeyPair keyPair = TestUtil.genEcKeys();

        // when
        final PsgPublicKeyBuilder builder = prepareBuilder(keyPair.getPublic().getEncoded());

        // then
        Assertions.assertNotNull(builder);
        Assertions.assertEquals(PSG_SHA384_FORMAT_LEN, builder.totalLen());
    }

    @Test
    void builder_WithEncodedRSAPubKey_ThrowsException() throws KeystoreGenericException {
        // given
        final KeyPair keyPair = TestUtil.genRsaKeys();

        // when-then
        Assertions.assertThrows(PsgPublicKeyBuilderException.class, () ->
            prepareBuilder(keyPair.getPublic().getEncoded()));
    }

    @Test
    void builder_WithEncodedECPubKeyXY_Success() {
        // when
        final PsgPublicKeyBuilder builder = prepareBuilderXY(getPubKeyXY());

        // then
        Assertions.assertNotNull(builder);
        Assertions.assertEquals(PSG_SHA384_FORMAT_LEN, builder.totalLen());
    }

    @Test
    void build_WithEcPubKey_Success() {
        // given
        final KeyPair keyPair = TestUtil.genEcKeys();
        final PsgPublicKeyBuilder builder = prepareBuilder(keyPair);

        // when
        final PsgPublicKey psgPublicKey = builder.build();

        // then
        Assertions.assertNotNull(psgPublicKey);
    }

    @Test
    void parse_WithEcPubKey_WithHexData_Success() throws PsgCertificateException {
        // given
        final KeyPair keyPair = TestUtil.genEcKeys();
        final byte[] preparedData = prepareBuilder(keyPair).build().array();

        // when
        final PsgPublicKeyBuilder publicKeyBuilder = new PsgPublicKeyBuilder()
            .parse(toHex(preparedData));

        // then
        Assertions.assertNotNull(publicKeyBuilder);
    }

    @Test
    void parse_WithEcPubKey_WithByteArrayData_Success() throws PsgCertificateException {
        // given
        final KeyPair keyPair = TestUtil.genEcKeys();
        final byte[] preparedData = prepareBuilder(keyPair).build().array();

        // when
        final PsgPublicKeyBuilder publicKeyBuilder = new PsgPublicKeyBuilder()
            .parse(preparedData);

        // then
        Assertions.assertNotNull(publicKeyBuilder);
    }


    @Test
    void verify_WithEcPubKey_Success() throws PsgCertificateException {
        // given
        final KeyPair keyPair = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_384);
        assert keyPair != null;
        final PsgPublicKeyBuilder publicKeyBuilder = new PsgPublicKeyBuilder()
            .withActor(EndianessActor.FIRMWARE)
            .magic(PsgPublicKeyMagic.MANIFEST_MAGIC)
            .curveType(PsgCurveType.SECP384R1)
            .permissions(ModifyBitsBuilder.fromNone().build())
            .publicKey((ECPublicKey) keyPair.getPublic());

        // when-then
        final PsgPublicKeyBuilder parsed = new PsgPublicKeyBuilder()
            .withActor(EndianessActor.FIRMWARE)
            .parse(publicKeyBuilder.build().array());

        Assertions.assertDoesNotThrow(parsed::verify);
    }

    private PsgPublicKeyBuilder prepareBuilder(KeyPair keyPair) {
        return new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.MANIFEST_MAGIC)
            .withActor(EndianessActor.SERVICE)
            .curveType(PsgCurveType.SECP384R1)
            .permissions(ModifyBitsBuilder.fromNone().build())
            .cancellation(PsgCancellation.CANCELLATION_ID_MIN)
            .publicKey((ECPublicKey) keyPair.getPublic());
    }

    private PsgPublicKeyBuilder prepareBuilder(byte[] encodedPublicKey) throws PsgPublicKeyBuilderException {
        return new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.MANIFEST_MAGIC)
            .withActor(EndianessActor.SERVICE)
            .curveType(PsgCurveType.SECP384R1)
            .permissions(ModifyBitsBuilder.fromNone().build())
            .cancellation(PsgCancellation.CANCELLATION_ID_MIN)
            .publicKey(encodedPublicKey);
    }

    private PsgPublicKeyBuilder prepareBuilderXY(byte[] publicKeyXY) {
        return new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.MANIFEST_MAGIC)
            .withActor(EndianessActor.SERVICE)
            .curveType(PsgCurveType.SECP384R1)
            .permissions(ModifyBitsBuilder.fromNone().build())
            .cancellation(PsgCancellation.CANCELLATION_ID_MIN)
            .publicKeyPointXY(publicKeyXY);
    }

    private byte[] getPubKeyXY() {
        PsgCurveType curveType = PsgCurveType.SECP384R1;
        byte[] pubKeyX = new byte[curveType.getSize()];
        byte[] pubKeyY = new byte[curveType.getSize()];
        new Random().nextBytes(pubKeyX);
        new Random().nextBytes(pubKeyY);
        return ByteBuffer.allocate(pubKeyX.length + pubKeyY.length).put(pubKeyX).put(pubKeyY).array();
    }

}
