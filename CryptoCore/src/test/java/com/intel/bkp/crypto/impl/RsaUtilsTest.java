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

package com.intel.bkp.crypto.impl;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.provider.TestProvider;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.Provider;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RsaUtilsTest {

    private static final String providerName = "test-provider";

    private Provider provider;

    @Test
    void genRSA_throwsBKPInternalServerExceptionDueToNoAlgorithm() {
        //given
        provider = new TestProvider(providerName, "1.0", "info");

        // then
        assertThrows(KeystoreGenericException.class, () -> RsaUtils.genRSA(CryptoConstants.RSA_KEY,
            CryptoConstants.RSA_KEY_SIZE, provider));
    }

    @Test
    void genRSA() throws KeystoreGenericException {
        //when
        KeyPair keyPair = RsaUtils.genRSA(CryptoConstants.RSA_KEY, CryptoConstants.RSA_KEY_SIZE,
            CryptoUtils.getBouncyCastleProvider());


        //then
        assertNotNull(keyPair);
    }

    @Test
    public void restoreRsaPubKey_Success() throws KeystoreGenericException {
        // given
        final KeyPair keyPair = CryptoUtils.genRsaBC();
        final PublicKey publicKey = keyPair.getPublic();

        // when
        PublicKey result = RsaUtils.restoreRSAPubKey(publicKey.getEncoded(), CryptoConstants.RSA_KEY,
            CryptoUtils.getBouncyCastleProvider());

        // then
        assertEquals(publicKey, result);
    }
}
