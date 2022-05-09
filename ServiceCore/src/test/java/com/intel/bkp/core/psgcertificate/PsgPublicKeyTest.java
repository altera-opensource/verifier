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
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPermissions;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Random;

import static com.intel.bkp.core.AssertArrays.assertThatArrayIsSubarrayOfAnotherArray;
import static com.intel.bkp.utils.HexConverter.toHex;

public class PsgPublicKeyTest {

    private final Random random = new Random();

    @Test
    void build_parse_withEncodedPublicKey_Success() throws Exception {
        // given
        PsgPublicKeyMagic magic = PsgPublicKeyMagic.MANIFEST_MAGIC;
        PsgCurveType curveType = PsgCurveType.SECP384R1;
        int permissions = PsgPermissions.SIGN_BKP_DH.getBitPosition();

        KeyPair keyPair = TestUtil.genEcKeys(null);
        assert keyPair != null;

        // when
        byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
        byte[] result = new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.MANIFEST_MAGIC)
            .curveType(PsgCurveType.SECP384R1)
            .permissions(permissions)
            .publicKey(encodedPublicKey)
            .build()
            .array();

        PsgPublicKeyBuilder parsed = new PsgPublicKeyBuilder().parse(result);

        // then
        Assertions.assertEquals(magic, parsed.getMagic());
        Assertions.assertEquals(curveType, parsed.getCurveType());
        assertThatArrayIsSubarrayOfAnotherArray(encodedPublicKey, parsed.getPointX());
        assertThatArrayIsSubarrayOfAnotherArray(encodedPublicKey, parsed.getPointY());
        Assertions.assertEquals(toHex(parsed.build().array()), parsed.build().toHex());
    }

    @Test
    void build_parse_withPublicKey_Success() throws Exception {
        // given
        PsgPublicKeyMagic magic = PsgPublicKeyMagic.MANIFEST_MAGIC;
        PsgCurveType curveType = PsgCurveType.SECP384R1;
        int permissions = PsgPermissions.SIGN_BKP_DH.getBitPosition();

        KeyPair keyPair = TestUtil.genEcKeys(null);
        assert keyPair != null;

        // when
        PublicKey publicKey = keyPair.getPublic();
        byte[] result = new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.MANIFEST_MAGIC)
            .curveType(PsgCurveType.SECP384R1)
            .permissions(permissions)
            .publicKey((ECPublicKey) publicKey)
            .build()
            .array();

        PsgPublicKeyBuilder parsed = new PsgPublicKeyBuilder().parse(result);

        // then
        Assertions.assertEquals(magic, parsed.getMagic());
        Assertions.assertEquals(curveType, parsed.getCurveType());
        assertThatArrayIsSubarrayOfAnotherArray(publicKey.getEncoded(), parsed.getPointX());
        assertThatArrayIsSubarrayOfAnotherArray(publicKey.getEncoded(), parsed.getPointY());
    }

    @Test
    void build_parse_withPublicKeyXY_Success() throws PsgCertificateException {
        // given
        PsgPublicKeyMagic magic = PsgPublicKeyMagic.MANIFEST_MAGIC;
        PsgCurveType curveType = PsgCurveType.SECP384R1;
        int permissions = PsgPermissions.SIGN_BKP_DH.getBitPosition();
        byte[] pubKeyX = new byte[curveType.getSize()];
        byte[] pubKeyY = new byte[curveType.getSize()];
        random.nextBytes(pubKeyX);
        random.nextBytes(pubKeyY);
        byte[] pubKeyXY = ByteBuffer.allocate(pubKeyX.length + pubKeyY.length).put(pubKeyX).put(pubKeyY).array();

        // when
        byte[] result = new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.MANIFEST_MAGIC)
            .curveType(PsgCurveType.SECP384R1)
            .permissions(permissions)
            .publicKeyPointXY(pubKeyXY)
            .build()
            .array();

        PsgPublicKeyBuilder parsed = new PsgPublicKeyBuilder().parse(result);

        // then
        Assertions.assertEquals(magic, parsed.getMagic());
        Assertions.assertEquals(curveType, parsed.getCurveType());
        Assertions.assertArrayEquals(pubKeyX, parsed.getPointX());
        Assertions.assertArrayEquals(pubKeyY, parsed.getPointY());
    }
}
