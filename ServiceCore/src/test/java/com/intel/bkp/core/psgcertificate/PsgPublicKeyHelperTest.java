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
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKey;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.core.utils.ModifyBitsBuilder;
import com.intel.bkp.crypto.constants.CryptoConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

class PsgPublicKeyHelperTest {

    private static final PsgCurveType TEST_CURVE_TYPE = PsgCurveType.SECP384R1;

    @Test
    void generateFingerprint_WithPsgPublicKeyArgument_Success() {
        // given
        final PsgPublicKey psgPubKey = generatePsgPublicKey().build();

        // when
        final String fingerprint = PsgPublicKeyHelper.generateFingerprint(psgPubKey);

        // then
        Assertions.assertNotNull(fingerprint);
        Assertions.assertEquals(96, fingerprint.length(), "Fingerprint for sha384 should be equal");
    }

    @Test
    void generateFingerprint_WithPsgPublicKeyBytesArgument_Success() throws PsgCertificateException {
        // given
        final byte[] psgPubKeyBytes = generatePsgPublicKey()
            .withActor(EndianessActor.SERVICE)
            .build()
            .array();

        // when
        final String fingerprint = PsgPublicKeyHelper.generateFingerprint(psgPubKeyBytes);

        // then
        Assertions.assertNotNull(fingerprint);
        Assertions.assertEquals(96, fingerprint.length(), "Fingerprint for sha384 should be equal");
    }

    @Test
    void generateFingerprint_WithPsgPublicKeyBuilderArgument_Success() {
        // given
        final PsgPublicKeyBuilder psgPublicKeyBuilder = generatePsgPublicKey();

        // when
        final String fingerprint = PsgPublicKeyHelper.generateFingerprint(psgPublicKeyBuilder);

        // then
        Assertions.assertNotNull(fingerprint);
        Assertions.assertEquals(96, fingerprint.length(), "Fingerprint for sha384 should be equal");
    }

    @Test
    void generateFingerprint_WithEcPublicKey_Success() {
        // given
        final KeyPair keyPair = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_384);
        assert keyPair != null;
        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, TEST_CURVE_TYPE);
        final String expected = PsgPublicKeyHelper.generateFingerprint(psgPublicKeyBuilder);

        // when
        final String result = PsgPublicKeyHelper.generateFingerprint((ECPublicKey) keyPair.getPublic());

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void parsePublicKeyMagic_WithManifestMagic_Success() throws PsgCertificateException {
        // given
        final PsgPublicKeyMagic expected = PsgPublicKeyMagic.MANIFEST_MAGIC;

        // when
        final PsgPublicKeyMagic actual = PsgPublicKeyHelper.parsePublicKeyMagic(expected.getValue());

        // then
        Assertions.assertEquals(expected, actual);
    }

    @Test
    void parsePublicKeyMagic_WithM1Magic_Success() throws PsgCertificateException {
        // given
        final PsgPublicKeyMagic expected = PsgPublicKeyMagic.M1_MAGIC;

        // when
        final PsgPublicKeyMagic actual = PsgPublicKeyHelper.parsePublicKeyMagic(expected.getValue());

        // then
        Assertions.assertEquals(expected, actual);
    }

    @Test
    void parsePublicKeyMagic_WithWrongPublicKeyMagic_ThrowsException() {
        Assertions.assertThrows(PsgCertificateException.class, () -> PsgPublicKeyHelper.parsePublicKeyMagic(123));
    }

    @Test
    void parseCurveType_WithPublicKeyArgument_Success() throws PsgCertificateException {
        // given
        final PsgPublicKey psgPubKey = generatePsgPublicKey()
            .withActor(EndianessActor.SERVICE)
            .build();

        // when
        final PsgCurveType actual = PsgPublicKeyHelper.parseCurveType(psgPubKey);

        // then
        Assertions.assertEquals(TEST_CURVE_TYPE, actual);
    }

    @Test
    void parseCurveType_WithBytesArgument_Success() throws PsgCertificateException {
        // given
        final PsgCurveType expected = PsgCurveType.SECP384R1;
        final ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES).putInt(expected.getMagic());

        // when
        final PsgCurveType actual = PsgPublicKeyHelper.parseCurveType(buffer.array());

        // then
        Assertions.assertEquals(expected, actual);
    }

    @Test
    void parseCurveType_WithIntArgumentAndSecp384r1_Success() throws PsgCertificateException {
        // given
        final PsgCurveType expected = PsgCurveType.SECP384R1;

        // when
        final PsgCurveType actual = PsgPublicKeyHelper.parseCurveType(expected.getMagic());

        // then
        Assertions.assertEquals(expected, actual);
    }

    @Test
    void parseCurveType_WithIntArgumentAndSecp256r1_Success() throws PsgCertificateException {
        // given
        final PsgCurveType expected = PsgCurveType.SECP256R1;

        // when
        final PsgCurveType actual = PsgPublicKeyHelper.parseCurveType(expected.getMagic());

        // then
        Assertions.assertEquals(expected, actual);
    }

    @Test
    void parseCurveType_WithIntArgument_ThrowException() {
        Assertions.assertThrows(PsgCertificateException.class, () -> PsgPublicKeyHelper.parseCurveType(123));
    }

    @Test
    void verifyPoint_Success() throws PsgCertificateException {
        // given
        final PsgPublicKeyBuilder psgPubKey = generatePsgPublicKey();

        // when
        PsgPublicKeyHelper.verifyPoint(psgPubKey);
    }

    @Test
    void verifyPoint_WithSecp256_Success() throws PsgCertificateException {
        // given
        final PsgPublicKeyBuilder psgPubKey = generatePsgPublicKeyForSecp256();

        // when
        PsgPublicKeyHelper.verifyPoint(psgPubKey);
    }

    @Test
    void areEquals_WithValidData_Success() {
        // given
        final KeyPair keyPair = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_384);
        assert keyPair != null;
        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, TEST_CURVE_TYPE);

        // when
        final boolean result = PsgPublicKeyHelper.areEqual((ECPublicKey) keyPair.getPublic(), psgPublicKeyBuilder);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void areEquals_WithInValidData_Throws() {
        // given
        final KeyPair keyPair = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_384);
        final KeyPair keyPairOther = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_384);
        assert keyPair != null;
        assert keyPairOther != null;
        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, TEST_CURVE_TYPE);

        // when
        final boolean result = PsgPublicKeyHelper.areEqual((ECPublicKey) keyPairOther.getPublic(), psgPublicKeyBuilder);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void verifyPoint_ThrowsException() {
        // when-then
        Assertions.assertThrows(PsgCertificateException.class,
            () -> PsgPublicKeyHelper.verifyPoint(new PsgPublicKeyBuilder()));
    }

    @Test
    void getTotalPublicKeySize_WithSecp384r1_Success() {
        // when
        final int actual = PsgPublicKeyHelper.getTotalPublicKeySize(PsgCurveType.SECP384R1);

        // then
        Assertions.assertEquals(120, actual, "Expected length for SECP384R1 with metadata");
    }

    @Test
    void getTotalPublicKeySize_WithSecp256r1_Success() {
        // when
        final int actual = PsgPublicKeyHelper.getTotalPublicKeySize(PsgCurveType.SECP256R1);

        // then
        Assertions.assertEquals(88, actual, "Expected length for SECP256R1 with metadata");
    }

    @Test
    void toPublic_WithPsgPublicKeyBytes_Success()
        throws NoSuchAlgorithmException, PsgCertificateException, InvalidKeySpecException {
        // given
        final byte[] psgPubKey = generatePsgPublicKey()
            .withActor(EndianessActor.SERVICE)
            .build()
            .array();

        // when
        final PublicKey publicKey = PsgPublicKeyHelper.toPublic(psgPubKey);

        // then
        Assertions.assertNotNull(publicKey);
    }

    @Test
    void toPublic_WithPsgPublicKeyObject_Success()
        throws NoSuchAlgorithmException, PsgCertificateException, InvalidKeySpecException {
        // given
        final PsgPublicKeyBuilder psgPubKey = generatePsgPublicKey();

        // when
        final PublicKey publicKey = PsgPublicKeyHelper.toPublic(psgPubKey);

        // then
        Assertions.assertNotNull(publicKey);
    }

    @Test
    void toPublic_WithPsgPublicKeyObjectAndSecp256_Success()
        throws NoSuchAlgorithmException, PsgCertificateException, InvalidKeySpecException {
        // given
        final PsgPublicKeyBuilder psgPubKey = generatePsgPublicKeyForSecp256();

        // when
        final PublicKey publicKey = PsgPublicKeyHelper.toPublic(psgPubKey);

        // then
        Assertions.assertNotNull(publicKey);
    }

    private PsgPublicKeyBuilder generatePsgPublicKey() {
        final KeyPair keyPair = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_384);
        assert keyPair != null;
        return getPsgPublicKeyBuilder(keyPair, TEST_CURVE_TYPE);
    }

    private PsgPublicKeyBuilder generatePsgPublicKeyForSecp256() {
        final KeyPair keyPair = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_256);
        assert keyPair != null;
        return getPsgPublicKeyBuilder(keyPair, PsgCurveType.SECP256R1);
    }

    private PsgPublicKeyBuilder getPsgPublicKeyBuilder(KeyPair keyPair, PsgCurveType testCurveType) {
        return new PsgPublicKeyBuilder()
            .withActor(EndianessActor.FIRMWARE)
            .magic(PsgPublicKeyMagic.MANIFEST_MAGIC)
            .curveType(testCurveType)
            .permissions(ModifyBitsBuilder.fromNone().build())
            .publicKey((ECPublicKey) keyPair.getPublic());
    }
}
