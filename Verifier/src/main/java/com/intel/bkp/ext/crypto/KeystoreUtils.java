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

import com.intel.bkp.ext.crypto.exceptions.KeystoreGenericException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

import static com.intel.bkp.ext.crypto.impl.CertificateUtils.getIssuer;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class KeystoreUtils {

    private static final long YEARS_TO_SECONDS = 365 * 24 * 3600L;
    private static final Provider bouncyCastleProvider = CryptoUtils.getBouncyCastleProvider();

    public static void storeKeyWithCertificate(Provider provider, KeyStore keyStore, KeyPair keyPair, String alias,
                                               long validityYears, String keyAlgorithm)
        throws KeystoreGenericException {

        storeKeyWithCertificate(provider, keyStore, keyPair.getPublic(), keyPair.getPrivate(),
            alias, validityYears, keyAlgorithm);
    }

    public static void storeKeyWithCertificate(Provider provider, KeyStore keyStore, PublicKey pubKey,
                                               PrivateKey privKey, String alias, long validityYears,
                                               String keyAlgorithm) throws KeystoreGenericException {
        try {
            X500Name issuer = getIssuer("self_sign_" + alias, "self_sign_" + alias);
            JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.probablePrime(160, new SecureRandom()),
                Date.from(Instant.now()),
                Date.from(Instant.now().plusSeconds(validityYears * YEARS_TO_SECONDS)),
                issuer,
                pubKey
            );

            ContentSigner contentSignerBuilder = new JcaContentSignerBuilder(keyAlgorithm)
                .setProvider(provider)
                .build(privKey);

            X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(bouncyCastleProvider)
                .getCertificate(
                    certificateBuilder
                        .build(contentSignerBuilder)
                );

            keyStore.setKeyEntry(alias, privKey, null, new Certificate[]{certificate});
        } catch (Exception e) {
            throw new KeystoreGenericException("Failed to store certificate with private key.", e);
        }
    }
}
