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

package com.intel.bkp.crypto;

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class CryptoUtilsTest {

    @Test
    public void genEcdhBC_Success() throws KeystoreGenericException {
        // when
        KeyPair result = CryptoUtils.genEcdhBC();

        // then
        assertNotNull(result);
        assertEquals(CryptoConstants.ECDH_KEY, result.getPrivate().getAlgorithm());
    }

    @Test
    public void genEcdsaBC_Success() throws KeystoreGenericException {
        // when
        KeyPair result = CryptoUtils.genEcdsaBC();

        // then
        assertNotNull(result);
        assertEquals(CryptoConstants.EC_KEY, result.getPrivate().getAlgorithm());
    }

    @Test
    public void genEcdhSharedSecretBC_Success() throws KeystoreGenericException {
        // given
        final KeyPair firstKeypair = CryptoUtils.genEcdhBC();
        final KeyPair secondKeypair = CryptoUtils.genEcdhBC();

        final PublicKey firstPublic = firstKeypair.getPublic();
        final PrivateKey firstPrivate = firstKeypair.getPrivate();

        final PublicKey secondPublic = secondKeypair.getPublic();
        final PrivateKey secondPrivate = secondKeypair.getPrivate();

        // when
        final byte[] bytesA = CryptoUtils.genEcdhSharedSecretBC(firstPrivate, secondPublic);
        final byte[] bytesB = CryptoUtils.genEcdhSharedSecretBC(secondPrivate, firstPublic);

        // then
        assertNotNull(bytesA);
        assertNotNull(bytesB);
        assertArrayEquals(bytesA, bytesB);
    }

    @Test
    void genRsaBC_Success() throws KeystoreGenericException {
        //when
        KeyPair keyPair = CryptoUtils.genRsaBC();

        //then
        assertNotNull(keyPair);
    }

    @Test
    public void restoreRSAPubKeyBC_Success() throws KeystoreGenericException {
        // given
        final KeyPair keyPair = CryptoUtils.genRsaBC();
        final PublicKey publicKey = keyPair.getPublic();

        // when
        PublicKey result = CryptoUtils.restoreRSAPubKeyBC(publicKey.getEncoded());

        // then
        assertEquals(publicKey, result);
    }

    @Test
    void genAesBC_Success() throws KeystoreGenericException {
        // when
        SecretKey result = CryptoUtils.genAesBC();

        // then
        assertNotNull(result);
        assertEquals(CryptoConstants.AES_KEY, result.getAlgorithm());
        assertEquals(CryptoConstants.AES_KEY_SIZE / 8, result.getEncoded().length);
    }

    @Test
    void getPubKeyXYLenForPubKey_With256() throws KeystoreGenericException {
        // given
        int expectedLen = 2 * CryptoConstants.SHA384_LEN;
        final KeyPair keyPair = CryptoUtils.genEcdsaBC(CryptoConstants.EC_CURVE_SPEC_384);

        // when
        final int result = CryptoUtils.getPubKeyXYLenForPubKey((ECPublicKey)keyPair.getPublic());

        // then
        assertEquals(expectedLen, result);
    }

    @Test
    void getPubKeyXYLenForPubKey_With384() throws KeystoreGenericException {
        // given
        int expectedLen = 2 * CryptoConstants.SHA256_LEN;
        final KeyPair keyPair = CryptoUtils.genEcdsaBC(CryptoConstants.EC_CURVE_SPEC_256);

        // when
        final int result = CryptoUtils.getPubKeyXYLenForPubKey((ECPublicKey)keyPair.getPublic());

        // then
        assertEquals(expectedLen, result);
    }
}
