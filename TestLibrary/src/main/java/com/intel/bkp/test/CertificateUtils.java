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
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.x509.generation.X509CertificateBuilder;
import com.intel.bkp.crypto.x509.generation.X509CertificateBuilderParams;
import lombok.SneakyThrows;
import org.apache.commons.lang3.time.DateUtils;

import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneOffset;
import java.util.Date;

import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.pemToX509Certificate;
import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509Certificate;
import static com.intel.bkp.crypto.x509.parsing.X509CrlParser.pemToX509Crl;
import static com.intel.bkp.crypto.x509.parsing.X509CrlParser.toX509Crl;
import static com.intel.bkp.test.FileUtils.readFromResources;

public class CertificateUtils {

    public static X509Certificate generateCertificate() {
        return generateCertificate(KeyGenUtils.genEc256());
    }

    @SneakyThrows
    public static X509Certificate generateCertificate(KeyPair keyPair) {
        return generateCertificate(keyPair, CryptoConstants.SHA384_WITH_ECDSA);
    }

    @SneakyThrows
    public static X509Certificate generateCertificate(KeyPair keyPair, String algorithm) {
        final var params = new X509CertificateBuilderParams(keyPair.getPublic());

        return new X509CertificateBuilder(params)
            .sign(keyPair.getPrivate(), CryptoUtils.getBouncyCastleProvider(), algorithm);
    }

    @SneakyThrows
    public static X509Certificate generateCertificate(KeyPair keyPair, String algorithm, boolean expired) {
        final var params = new X509CertificateBuilderParams(keyPair.getPublic())
            .withNotBefore(DateUtils.addDays(new Date(), -2))
            .withNotAfter(DateUtils.addDays(new Date(), expired ? -1 : 1));

        return new X509CertificateBuilder(params)
            .sign(keyPair.getPrivate(), CryptoUtils.getBouncyCastleProvider(), algorithm);
    }

    public static X509Certificate generateExpiredCertificate() {
        return generateCertificate(KeyGenUtils.genEc256(), CryptoConstants.SHA256_WITH_ECDSA, true);
    }

    @SneakyThrows
    public static X509Certificate readCertificate(String folder, String filename) {
        return toX509Certificate(readFromResources(folder, filename));
    }

    public static X509CRL readCrl(String folder, String filename) throws Exception {
        return toX509Crl(readFromResources(folder, filename));
    }

    @SneakyThrows
    public static X509Certificate convertToCert(String certInPem) {
        return pemToX509Certificate(certInPem);
    }

    @SneakyThrows
    public static X509CRL convertToCrl(String crlInPem) {
        return pemToX509Crl(crlInPem);
    }

    public static Date getEndOfTimeDate() {
        long endOfTimeEpochMillis = LocalDate.of(9999, Month.DECEMBER, 31)
            .atStartOfDay()
            .toInstant(ZoneOffset.UTC)
            .toEpochMilli();
        return new Date(endOfTimeEpochMillis);
    }
}
