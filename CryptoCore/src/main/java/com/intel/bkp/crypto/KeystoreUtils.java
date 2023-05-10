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

package com.intel.bkp.crypto;

import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.x509.generation.X509CertificateBuilder;
import com.intel.bkp.crypto.x509.generation.X509CertificateBuilderParams;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.Enumeration;

import static com.intel.bkp.crypto.impl.CertificateUtils.getIssuer;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class KeystoreUtils {

    private static final long YEARS_TO_SECONDS = 365 * 24 * 3600L;

    public static void storeSecretKey(KeyStore keyStore, SecretKey secretKey, String alias)
        throws KeystoreGenericException {
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
        try {
            keyStore.setEntry(alias, skEntry, new KeyStore.PasswordProtection("".toCharArray()));
        } catch (Exception e) {
            throw new KeystoreGenericException("Failed to create AES key in secure enclave.", e);
        }
    }

    public static Enumeration<String> listSecurityObjects(KeyStore keyStore) {
        try {
            return keyStore.aliases();
        } catch (KeyStoreException e) {
            return null;
        }
    }

    public static void storeKeyWithCertificate(Provider provider, KeyStore keyStore, KeyPair keyPair,
        String alias, long validityYears, String keyAlgorithm) throws KeystoreGenericException {
        storeKeyWithCertificate(provider, keyStore, keyPair.getPublic(), keyPair.getPrivate(),
            alias, validityYears, keyAlgorithm);
    }

    public static void storeKeyWithCertificate(Provider provider, KeyStore keyStore, PublicKey pubKey,
        PrivateKey privKey, String alias, long validityYears, String keyAlgorithm) throws KeystoreGenericException {
        try {
            final var issuer = getIssuer("self_sign_" + alias, "self_sign_" + alias);

            final var params = new X509CertificateBuilderParams(pubKey)
                .withIssuerName(issuer)
                .withSubjectName(issuer)
                .withSerialNumber(BigInteger.probablePrime(160, new SecureRandom()))
                .withNotAfter(Date.from(Instant.now().plusSeconds(validityYears * YEARS_TO_SECONDS)));

            final var certificate = new X509CertificateBuilder(params)
                .sign(privKey, provider, keyAlgorithm);

            keyStore.setKeyEntry(alias, privKey, null, new Certificate[]{certificate});
        } catch (Exception e) {
            throw new KeystoreGenericException("Failed to store certificate with private key.", e);
        }
    }
}
