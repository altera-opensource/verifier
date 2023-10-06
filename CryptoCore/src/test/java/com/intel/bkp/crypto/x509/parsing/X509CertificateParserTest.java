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

package com.intel.bkp.crypto.x509.parsing;

import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.enumeration.ResourceDir;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X509CertificateParserTest {

    // https://tsci.intel.com/content/IPCS/certs/IPCS.cer
    private static final String PEM_CERT_FILENAME = "IPCS.cer";
    private static final String PEM_CERT_SUBJECT = "CN=IPCS Root Signing,OU=Intel PUF Certificate Service,"
        + "O=Intel Corporation,L=Santa Clara,ST=CA,C=US";

    // https://tsci.intel.com/content/IPCS/certs/IPCSSigningCA.cer
    private static final String DER_CERT_FILENAME = "IPCSSigningCA.cer";
    private static final String DER_CERT_SUBJECT = "CN=IPCS Signing Cert Test,OU=Intel PUF Certificate Service," +
        "O=Intel Corporation,L=Santa Clara,ST=CA,C=US";

    private static String certPemString;
    private static byte[] certPemEncoded;
    private static byte[] certDerEncoded;

    @BeforeAll
    static void init() {
        certPemString = FileUtils.loadFile(ResourceDir.CERTS, PEM_CERT_FILENAME);
        certPemEncoded = FileUtils.loadBinary(ResourceDir.CERTS, PEM_CERT_FILENAME);
        certDerEncoded = FileUtils.loadBinary(ResourceDir.CERTS, DER_CERT_FILENAME);
    }

    @Test
    void pemToX509Certificate_PemCert_Success() throws X509CertificateParsingException {
        // when
        final X509Certificate result = X509CertificateParser.pemToX509Certificate(certPemString);

        // then
        assertEquals(PEM_CERT_SUBJECT, result.getSubjectX500Principal().getName());
    }

    @Test
    void pemToX509Certificate_EmptyString_ReturnsNull() throws X509CertificateParsingException {
        // when
        final X509Certificate result = X509CertificateParser.pemToX509Certificate("");

        // then
        assertNull(result);
    }

    @Test
    void pemToX509Certificate_InvalidInput_Throws() {
        // when-then
        assertThrows(X509CertificateParsingException.class,
            () -> X509CertificateParser.pemToX509Certificate("not a crl in pem"));
    }

    @Test
    void toX509Certificate_PemCert_Success() throws X509CertificateParsingException {
        // when
        final X509Certificate result = X509CertificateParser.toX509Certificate(certPemEncoded);

        // then
        assertEquals(PEM_CERT_SUBJECT, result.getSubjectX500Principal().getName());
    }

    @Test
    void toX509Certificate_DerCert_Success() throws X509CertificateParsingException {
        // when
        final X509Certificate result = X509CertificateParser.toX509Certificate(certDerEncoded);

        // then
        assertEquals(DER_CERT_SUBJECT, result.getSubjectX500Principal().getName());
    }

    @Test
    void toX509Certificate_InvalidInput_Throws() {
        // when-then
        assertThrows(X509CertificateParsingException.class,
            () -> X509CertificateParser.toX509Certificate(new byte[]{0x01, 0x02}));
    }

    @Test
    void tryToX509_WithString_PemCert_Success() {
        // when
        final Optional<X509Certificate> result = X509CertificateParser.tryToX509(certPemString);

        // then
        assertTrue(result.isPresent());
        assertEquals(PEM_CERT_SUBJECT, result.get().getSubjectX500Principal().getName());
    }

    @Test
    void tryToX509_WithString_InvalidInput_ReturnsEmpty() {
        // when
        final Optional<X509Certificate> result = X509CertificateParser.tryToX509("not a valid cert");

        // then
        assertTrue(result.isEmpty());
    }

    @Test
    void tryToX509_WithBytes_DerCert_Success() {
        // when
        final Optional<X509Certificate> result = X509CertificateParser.tryToX509(certDerEncoded);

        // then
        assertTrue(result.isPresent());
        assertEquals(DER_CERT_SUBJECT, result.get().getSubjectX500Principal().getName());
    }

    @Test
    void tryToX509_WithBytes_PemCert_Success() {
        // when
        final Optional<X509Certificate> result = X509CertificateParser.tryToX509(certPemEncoded);

        // then
        assertTrue(result.isPresent());
        assertEquals(PEM_CERT_SUBJECT, result.get().getSubjectX500Principal().getName());
    }

    @Test
    void tryToX509_WithBytes_InvalidInput_ReturnsEmptyOptional() {
        // when
        final Optional<X509Certificate> result = X509CertificateParser.tryToX509(new byte[]{0x01, 0x02});

        // then
        assertTrue(result.isEmpty());
    }

    @Test
    void toX509CertificateChain_ChainWithSingleCert_Success() throws X509CertificateParsingException {
        // when
        final List<X509Certificate> result = X509CertificateParser.toX509CertificateChain(certDerEncoded);

        // then
        assertEquals(1, result.size());
        assertEquals(DER_CERT_SUBJECT, result.get(0).getSubjectX500Principal().getName());
    }

    @Test
    void toX509CertificateChain_ChainWithMultipleCerts_Success() throws X509CertificateParsingException {
        // given
        final byte[] chainBytes = ArrayUtils.addAll(certDerEncoded, certPemEncoded);

        // when
        final List<X509Certificate> result = X509CertificateParser.toX509CertificateChain(chainBytes);

        // then
        assertEquals(2, result.size());
        assertEquals(DER_CERT_SUBJECT, result.get(0).getSubjectX500Principal().getName());
        assertEquals(PEM_CERT_SUBJECT, result.get(1).getSubjectX500Principal().getName());
    }

    @Test
    void toX509CertificateChain_InvalidInput_Throws() {
        // when-then
        assertThrows(X509CertificateParsingException.class,
            () -> X509CertificateParser.toX509CertificateChain(new byte[]{0x01, 0x02}));
    }
}
