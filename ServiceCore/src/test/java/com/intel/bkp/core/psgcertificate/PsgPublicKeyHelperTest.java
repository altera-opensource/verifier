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
import com.intel.bkp.core.exceptions.PublicKeyHelperException;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.core.utils.ModifyBitsBuilder;
import com.intel.bkp.crypto.constants.CryptoConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

class PsgPublicKeyHelperTest {

    private static final PsgCurveType TEST_CURVE_TYPE = PsgCurveType.SECP384R1;

    @Test
    void generateFingerprint_WithPsgPublicKeyBuilderArgument_Success() {
        // given
        final PsgPublicKeyBuilder psgPublicKeyBuilder = generatePsgPublicKey();

        // when
        final String fingerprint = PsgPublicKeyHelper.from(psgPublicKeyBuilder).generateFingerprint();

        // then
        Assertions.assertNotNull(fingerprint);
        Assertions.assertEquals(96, fingerprint.length(), "Fingerprint for sha384 should be equal");
    }

    @Test
    void verifyPoint_Success() throws PublicKeyHelperException {
        // given
        final PsgPublicKeyBuilder psgPubKey = generatePsgPublicKey();

        // when
        PsgPublicKeyHelper.from(psgPubKey).verifyPoint();
    }

    @Test
    void verifyPoint_WithSecp256_Success() throws PublicKeyHelperException {
        // given
        final PsgPublicKeyBuilder psgPubKey = generatePsgPublicKeyForSecp256();

        // when
        PsgPublicKeyHelper.from(psgPubKey).verifyPoint();
    }

    @Test
    void areEquals_WithValidData_Success() {
        // given
        final KeyPair keyPair = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_384);
        assert keyPair != null;
        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, TEST_CURVE_TYPE);

        // when
        final boolean result = PsgPublicKeyHelper.from(psgPublicKeyBuilder).areEqual((ECPublicKey) keyPair.getPublic());

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
        final boolean result =
            PsgPublicKeyHelper.from(psgPublicKeyBuilder).areEqual((ECPublicKey) keyPairOther.getPublic());

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void toPublic_WithPsgPublicKeyObject_Success() throws PublicKeyHelperException {
        // given
        final PsgPublicKeyBuilder psgPubKey = generatePsgPublicKey();

        // when
        final PublicKey publicKey = PsgPublicKeyHelper.from(psgPubKey).toPublic();

        // then
        Assertions.assertNotNull(publicKey);
    }

    @Test
    void toPublic_WithPsgPublicKeyObjectAndSecp256_Success() throws PublicKeyHelperException {
        // given
        final PsgPublicKeyBuilder psgPubKey = generatePsgPublicKeyForSecp256();

        // when
        final PublicKey publicKey = PsgPublicKeyHelper.from(psgPubKey).toPublic();

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
            .withActor(EndiannessActor.FIRMWARE)
            .magic(PsgPublicKeyMagic.MANIFEST_MAGIC)
            .permissions(ModifyBitsBuilder.fromNone().build())
            .publicKey(keyPair.getPublic(), testCurveType);
    }
}
