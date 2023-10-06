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

package com.intel.bkp.fpgacerts.cbor;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.signer.cose.exception.CoseException;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.KeyKeys;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_256;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_384;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_521;
import static com.intel.bkp.crypto.constants.SecurityKeyType.EC;

public class OneKeyGenerator {

    public static CborKeyPair generate(AlgorithmId algorithm) throws CoseException {
        final CborKeyPair cborKeyPair = switch (algorithm) {
            case ECDSA_256 -> generateOneKey(EC_CURVE_SPEC_256);
            case ECDSA_384 -> generateOneKey(EC_CURVE_SPEC_384);
            case ECDSA_521 -> generateOneKey(EC_CURVE_SPEC_521);
        };
        cborKeyPair.add(KeyKeys.ALGORITHM, algorithm.getCbor());
        return cborKeyPair;
    }

    private static CborKeyPair generateOneKey(String curveName) throws CoseException {
        try {
            final var gen = KeyPairGenerator.getInstance(EC.name(), CryptoUtils.getBouncyCastleProvider());
            gen.initialize(new ECGenParameterSpec(curveName));
            final var keyPair = gen.genKeyPair();
            return CborKeyPair.fromKeyPair(keyPair.getPublic(), keyPair.getPrivate());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new CoseException("Failed to initialize keypair generator", e);
        }
    }
}
