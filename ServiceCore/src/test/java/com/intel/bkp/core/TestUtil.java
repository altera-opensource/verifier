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

package com.intel.bkp.core;

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.impl.EcUtils;
import com.intel.bkp.crypto.impl.RsaUtils;
import com.intel.bkp.crypto.x509.generation.X509CertificateBuilder;
import com.intel.bkp.crypto.x509.generation.X509CertificateBuilderParams;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Random;

import static com.intel.bkp.crypto.CryptoUtils.getBouncyCastleProvider;
import static com.intel.bkp.crypto.constants.CryptoConstants.ECDSA_KEY;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_384;
import static com.intel.bkp.crypto.constants.CryptoConstants.RSA_KEY;
import static com.intel.bkp.crypto.constants.CryptoConstants.RSA_KEY_SIZE;

/**
 * Utility class for testing.
 */
public class TestUtil {

    @SneakyThrows
    public static X509Certificate genSelfSignedCert(KeyPair keyPair) {
        final var params = new X509CertificateBuilderParams(keyPair.getPublic());

        return new X509CertificateBuilder(params)
            .sign(keyPair.getPrivate());
    }

    @SneakyThrows
    public static byte[] loadBinaryFile(String filePath) {
        return IOUtils.toByteArray(TestUtil.class.getResourceAsStream(filePath));
    }

    public static KeyPair genEcKeys() {
        return genEcKeys(EC_CURVE_SPEC_384);
    }

    public static KeyPair genEcKeys(String paramSpec) {
        if (StringUtils.isEmpty(paramSpec)) {
            paramSpec = EC_CURVE_SPEC_384;
        }

        try {
            return EcUtils.genEc(getBouncyCastleProvider(), ECDSA_KEY, paramSpec);
        } catch (KeystoreGenericException e) {
            throw new RuntimeException("Failed to generate EC keys", e);
        }
    }

    public static KeyPair genRsaKeys() throws KeystoreGenericException {
        return RsaUtils.genRSA(RSA_KEY, RSA_KEY_SIZE, getBouncyCastleProvider());
    }

    public static byte[] signEcData(byte[] msg, PrivateKey priv, String sigAlgorithmName) {
        if (StringUtils.isEmpty(sigAlgorithmName)) {
            sigAlgorithmName = CryptoConstants.SHA384_WITH_ECDSA;
        }

        try {
            return EcUtils.signEcData(priv, msg, sigAlgorithmName, getBouncyCastleProvider());
        } catch (KeystoreGenericException e) {
            throw new RuntimeException("Failed to sign data");
        }
    }

    public static byte[] generateRandomData(int length) {
        final byte[] data = new byte[length];
        new Random().nextBytes(data);
        return data;
    }
}
