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

package com.intel.bkp.test;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.SecurityKeyType;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EcKeyLoader {

    private static String getKey(InputStream is) throws IOException {
        final StringBuilder pemData = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                pemData.append(line).append("\n");
            }
        }
        return pemData.toString();
    }

    public static PrivateKey getPrivateKey(InputStream fileStream) throws IOException, GeneralSecurityException {
        final String privateKeyPemData = getKey(fileStream);
        return getPrivateKeyFromString(privateKeyPemData);
    }

    public static PublicKey getPublicKey(InputStream fileStream) throws GeneralSecurityException, IOException {
        return getPublicKeyContentFromString(fileStream);
    }

    private static byte[] decodeKey(String pubKey) {
        pubKey = pubKey
            .replaceAll("([\\-]+)([A-Z\\s]+)([\\-]+)", "")
            .replaceAll(System.lineSeparator(), "");
        return Base64.getDecoder().decode(pubKey);
    }

    private static PublicKey getPublicKeyContentFromString(InputStream fileStream)
        throws GeneralSecurityException, IOException {
        return KeyFactory.getInstance(SecurityKeyType.EC.name(), CryptoUtils.getBouncyCastleProvider())
            .generatePublic(new X509EncodedKeySpec(decodeKey(getKey(fileStream))));
    }

    private static PrivateKey getPrivateKeyFromString(String key) throws GeneralSecurityException {
        return KeyFactory.getInstance(SecurityKeyType.EC.name(),
            CryptoUtils.getBouncyCastleProvider()).generatePrivate(new PKCS8EncodedKeySpec(decodeKey(key)));
    }
}
