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

package com.intel.bkp.crypto.ecdh;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

import static com.intel.bkp.crypto.constants.CryptoConstants.ECDH_KEY;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_384;

@Getter
@Setter
@NoArgsConstructor
public class EcdhKeyPair {

    private static final String KEY_IS_NOT_SET = "Key is not set.";
    private static final int DH_PUB_KEY_LEN = 96;

    private byte[] publicKey;
    private byte[] privateKey;

    public EcdhKeyPair(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    private EcdhKeyPair(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public static EcdhKeyPair generate() throws EcdhKeyPairException {
        try {
            KeyPair keyPair = CryptoUtils.genEcdhBC();
            while (!(EcdhVerifier.isValid((ECPrivateKey) keyPair.getPrivate()))) {
                keyPair = CryptoUtils.genEcdhBC();
            }
            return EcdhKeyPair.fromKeyPair(keyPair);
        } catch (KeystoreGenericException e) {
            throw new EcdhKeyPairException("Failed to create ECDH keypair.", e);
        }
    }

    public static EcdhKeyPair fromKeyPair(KeyPair keyPair) throws EcdhKeyPairException {
        return Optional.ofNullable(keyPair)
            .map(kp -> new EcdhKeyPair(CryptoUtils.getBytesFromPubKey((ECPublicKey) kp.getPublic(), DH_PUB_KEY_LEN),
                CryptoUtils.getBytesFromPrivKey((ECPrivateKey) kp.getPrivate())))
            .orElseThrow(() -> new EcdhKeyPairException("Parameter 'keyPair' is null."));
    }

    public static EcdhKeyPair fromPublicBytes(byte[] publicKey) throws EcdhKeyPairException {
        validate(publicKey);
        return new EcdhKeyPair(publicKey);
    }

    private static void validate(byte[] param) throws EcdhKeyPairException {
        if (param == null || param.length == 0) {
            throw new EcdhKeyPairException(KEY_IS_NOT_SET);
        }
    }

    public PublicKey publicKey() throws EcdhKeyPairException {
        validate(publicKey);
        try {
            return CryptoUtils.toEcPublicBC(publicKey, ECDH_KEY, getCurveSpec());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new EcdhKeyPairException("Failed to create public key from bytes.", e);
        }
    }

    private static String getCurveSpec() {
        return EC_CURVE_SPEC_384;
    }

    public PrivateKey privateKey() throws EcdhKeyPairException {
        validate(privateKey);
        try {
            return CryptoUtils.toEcPrivateBC(privateKey, ECDH_KEY);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new EcdhKeyPairException("Failed to create private key from bytes.", e);
        }
    }
}
