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

package com.intel.bkp.crypto.rsa;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class RsaEncryptionProviderTest {

    private static final String BOUNCYCASTLE_RSA_OAEP_CIPHER = "RSA/None/OAEPWithSHA384AndMGF1Padding";
    private static final Provider BOUNCY_CASTLE_PROVIDER = CryptoUtils.getBouncyCastleProvider();
    private static PublicKey RSA_PUBLIC;
    private static PrivateKey RSA_PRIVATE;

    @BeforeAll
    public static void setUpClass() throws KeystoreGenericException {
        final KeyPair rsaKeyPair = CryptoUtils.genRsaBC();
        RSA_PUBLIC = rsaKeyPair.getPublic();
        RSA_PRIVATE = rsaKeyPair.getPrivate();
    }

    @Test
    public void encrypt_decrypt_Success() throws EncryptionProviderException {
        // given
        final byte[] data = new byte[]{1, 0, 0, 1, 0, 0, 1, 1};
        RsaEncryptionProvider encryptionprovider = new RsaEncryptionProvider(RSA_PUBLIC, BOUNCY_CASTLE_PROVIDER,
            BOUNCYCASTLE_RSA_OAEP_CIPHER);
        RsaEncryptionProvider decryptionProvider = new RsaEncryptionProvider(RSA_PRIVATE, BOUNCY_CASTLE_PROVIDER,
            BOUNCYCASTLE_RSA_OAEP_CIPHER);

        // when
        byte[] encrypted = encryptionprovider.encrypt(data);
        byte[] result = decryptionProvider.decrypt(encrypted);

        // then
        assertArrayEquals(data, result);
    }

}
