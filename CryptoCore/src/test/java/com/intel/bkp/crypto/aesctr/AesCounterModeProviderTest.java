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

package com.intel.bkp.crypto.aesctr;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.Provider;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;

public class AesCounterModeProviderTest {

    // Secret key, plaintext, ciphertext and iv - NIST.SP.800-38a.pdf
    private byte[] plaintext = fromHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        + "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    private byte[] ciphertext = fromHex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
        + "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6");
    private byte[] iv = fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    private byte[] key = fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");

    private AesCounterModeProvider sut = new AesCounterModeProvider() {

        private SecretKey secretKey = CryptoUtils.genAesKeyFromByteArray(key);
        private IIvProvider iv = () -> AesCounterModeProviderTest.this.iv;

        @Override
        public SecretKey getSecretKey() {
            return secretKey;
        }

        @Override
        public Provider getProvider() {
            return CryptoUtils.getBouncyCastleProvider();
        }

        @Override
        public String getCipherType() {
            return "AES/CTR/NoPadding";
        }

        @Override
        public IIvProvider getIvProvider() {
            return iv;
        }
    };

    private boolean compareArrays(byte[] arrIsIn, byte[] arr) {
        return toHex(arr).contains(toHex(arrIsIn));
    }

    @Test
    public void encrypt_Success() throws EncryptionProviderException {
        // when
        final byte[] result = sut.encrypt(plaintext);

        // then
        Assertions.assertTrue(compareArrays(ciphertext, result));
    }

    @Test
    public void decrypt_Success() throws EncryptionProviderException {
        // when
        final byte[] result = sut.decrypt(ciphertext);

        // then
        Assertions.assertTrue(compareArrays(plaintext, result));
    }
}
