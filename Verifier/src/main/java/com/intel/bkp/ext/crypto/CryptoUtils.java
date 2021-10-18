/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.ext.crypto;

import com.intel.bkp.ext.crypto.constants.CryptoConstants;
import com.intel.bkp.ext.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.ext.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.ext.crypto.impl.EcUtils;
import com.intel.bkp.ext.crypto.impl.HashUtils;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public abstract class CryptoUtils {

    @Getter
    protected static Provider bouncyCastleProvider = new BouncyCastleProvider();

    public static KeyPair genEcdhBC() throws KeystoreGenericException {
        return EcUtils.genEc(bouncyCastleProvider, CryptoConstants.ECDH_KEY, CryptoConstants.EC_CURVE_SPEC_384);
    }

    public static KeyPair genEcdsaBC() throws KeystoreGenericException {
        return EcUtils.genEc(bouncyCastleProvider, CryptoConstants.ECDSA_KEY, CryptoConstants.EC_CURVE_SPEC_384);
    }

    public static org.bouncycastle.math.ec.ECPoint getCurveGenerator(String curveType) {
        return EcUtils.getCurveGenerator(curveType);
    }

    public static PublicKey toEcPublicBC(byte[] publicKeyBytes, String algorithm, String curveType)
        throws NoSuchAlgorithmException, InvalidKeySpecException, EcdhKeyPairException {
        return EcUtils.toPublic(publicKeyBytes, algorithm, curveType, bouncyCastleProvider);
    }

    public static byte[] getBytesFromPubKey(ECPublicKey publicKey, int dhPubKeyLen) {
        return EcUtils.getBytesFromPubKey(publicKey, dhPubKeyLen, CryptoConstants.SHA384_LEN);
    }

    public static byte[] getBytesFromPrivKey(ECPrivateKey privateKey) {
        return EcUtils.getBytesFromPrivKey(privateKey);
    }

    public static String generateSha256Fingerprint(byte[] data) {
        return HashUtils.generateSha256Fingerprint(data);
    }

    public static byte[] get20MSBytesForSha384(byte[] data) {
        return HashUtils.get20MSBytesForSha384(data);
    }
}
