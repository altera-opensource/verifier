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

package com.intel.bkp.crypto.impl;

import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RsaUtils {

    public static KeyPair genRSA(String rsaKeyName, int rsaKeySize, Provider provider) throws KeystoreGenericException {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(rsaKeyName, provider);
            kpg.initialize(rsaKeySize, new SecureRandom());
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new KeystoreGenericException("Failed to create RSA key in secure enclave.", e);
        }
    }

    public static PublicKey restoreRSAPubKey(byte[] rsaKey, String rsaKeyName, Provider provider)
        throws KeystoreGenericException {
        try {
            KeyFactory kf = KeyFactory.getInstance(rsaKeyName, provider);
            KeySpec keySpec = new X509EncodedKeySpec(rsaKey);
            return kf.generatePublic(keySpec);
        } catch (Exception e) {
            throw new KeystoreGenericException("Failed to restore RSA key.", e);
        }
    }
}
