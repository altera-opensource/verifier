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
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static com.intel.bkp.crypto.CryptoUtils.getBouncyCastleProvider;
import static com.intel.bkp.crypto.constants.CryptoConstants.AES_KEY;
import static com.intel.bkp.crypto.constants.CryptoConstants.AES_KEY_SIZE;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_256;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_384;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_KEY;
import static com.intel.bkp.crypto.constants.CryptoConstants.RSA_KEY;
import static com.intel.bkp.crypto.constants.CryptoConstants.RSA_KEY_SIZE;
import static com.intel.bkp.crypto.impl.AesUtils.genAES;
import static com.intel.bkp.crypto.impl.EcUtils.genEc;
import static com.intel.bkp.crypto.impl.PublicKeyUtils.toPublicEncoded;
import static com.intel.bkp.crypto.impl.RsaUtils.genRSA;
import static com.intel.bkp.utils.HexConverter.fromHex;

public class KeyGenUtils {

    public static KeyPair genEc384() {
        return generateEcKey(EC_CURVE_SPEC_384);
    }

    @SneakyThrows
    public static KeyPair generateEcKey(String paramSpec) {
        if (StringUtils.isEmpty(paramSpec)) {
            paramSpec = EC_CURVE_SPEC_384;
        }
        return genEc(getBouncyCastleProvider(), EC_KEY, paramSpec);
    }

    @SneakyThrows
    public static KeyPair genRsa3072() {
        return genRSA(RSA_KEY, RSA_KEY_SIZE, getBouncyCastleProvider());
    }

    @SneakyThrows
    public static KeyPair genRsa1024() {
        return genRSA(RSA_KEY, 1024, getBouncyCastleProvider());
    }

    public static KeyPair genEc256() {
        return generateEcKey(EC_CURVE_SPEC_256);
    }

    public static SecretKey genAes256() throws KeystoreGenericException {
        return genAES(getBouncyCastleProvider(), AES_KEY, AES_KEY_SIZE);
    }

    public static SecretKey genAesKeyFromBase64(String base64EncodedKey) {
        final byte[] decodedKey = Base64.getDecoder().decode(base64EncodedKey);
        return CryptoUtils.genAesKeyFromByteArray(decodedKey);
    }

    public static PrivateKey getPrivateKeyFromHex(String keyHex) throws Exception {
        KeyFactory factory = KeyFactory.getInstance(SecurityKeyType.EC.name(),
            CryptoUtils.getBouncyCastleProvider());
        return factory.generatePrivate(new PKCS8EncodedKeySpec(fromHex(keyHex)));
    }

    public static PublicKey getPublicKeyFromHex(String keyHex) throws Exception {
        return toPublicEncoded(fromHex(keyHex), SecurityKeyType.EC.name(), CryptoUtils.getBouncyCastleProvider());
    }
}
