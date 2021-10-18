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

package com.intel.bkp.verifier.x509;

import com.intel.bkp.verifier.Utils;
import com.intel.bkp.verifier.exceptions.X509ParsingException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.Optional;

@ExtendWith(MockitoExtension.class)
class X509CertificateParserTest {

    private static final String TEST_FOLDER = "certs/";
    private static final String DUMMY_CHAIN_FOLDER = "dummyChain/";

    // https://tsci.intel.com/content/IPCS/certs/IPCSSigningCA.cer
    private static final String PARENT_CERT_FILENAME = "IPCSSigningCA.cer";
    private static final String CERT_SUBJECT = "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,OU=Intel PUF " +
        "Certificate Service,CN=IPCS Signing Cert Test";
    private static final String ISSUER_CERT_LOCATION = "https://tsci.intel.com/content/IPCS/certs/IPCS.cer";
    private static final String CRL_DISTRIBUTION_POINT_ADDRESS = "https://tsci.intel.com/content/IPCS/crls/IPCS" +
        ".crl";
    private static final String CRL_DISTRIBUTION_POINT_ADDRESS_DUMMY = "http://green.no/ca/email-ca.crl";

    private static byte[] certificate;
    private static byte[] dummyCertificate;
    private static byte[] dummyCertificateNoCrlExtension;
    private static byte[] dummyCertificateEmptyCrlPath;

    @InjectMocks
    private X509CertificateParser sut;

    @BeforeAll
    static void init() throws Exception {
        certificate = Utils.readFromResources(TEST_FOLDER, PARENT_CERT_FILENAME);

        // certificate chain generated based on tutorial https://pki-tutorial.readthedocs.io/en/latest/advanced/
        dummyCertificate = Utils.readFromResources(TEST_FOLDER + DUMMY_CHAIN_FOLDER, "leaf-not-revoked.crt");
        dummyCertificateNoCrlExtension = Utils.readFromResources(TEST_FOLDER + DUMMY_CHAIN_FOLDER, "leaf-no-crl.crt");
        dummyCertificateEmptyCrlPath = Utils.readFromResources(TEST_FOLDER + DUMMY_CHAIN_FOLDER, "leaf-crl-empty-path" +
            ".crt");
    }

    @Test
    void toX509() {
        // when
        X509Certificate result = sut.toX509(certificate);

        // then
        Assertions.assertEquals(CERT_SUBJECT, result.getSubjectDN().toString());
    }

    @Test
    void toX509_ParsingFailed_Throws() {
        // when-then
        Assertions.assertThrows(X509ParsingException.class, () -> sut.toX509(new byte[]{1, 2}));
    }

    @Test
    void getPathToIssuerCertificateLocation() {
        // when
        String result = sut.getPathToIssuerCertificateLocation(sut.toX509(certificate));

        // then
        Assertions.assertEquals(ISSUER_CERT_LOCATION, result);
    }

    @Test
    void getPathToCrlDistributionPoint() {
        // when
        Optional<String> result = sut.getPathToCrlDistributionPoint(sut.toX509(certificate));

        // then
        Assertions.assertTrue(result.isPresent());
        Assertions.assertEquals(CRL_DISTRIBUTION_POINT_ADDRESS, result.get());
    }

    @Test
    void getPathToCrlDistributionPoint_dummyCert() {
        // when
        Optional<String> result = sut.getPathToCrlDistributionPoint(sut.toX509(dummyCertificate));

        // then
        Assertions.assertTrue(result.isPresent());
        Assertions.assertEquals(CRL_DISTRIBUTION_POINT_ADDRESS_DUMMY, result.get());
    }

    @Test
    void getPathToCrlDistributionPoint_dummyCert_withoutCrlExtension() {
        // when
        Optional<String> result = sut.getPathToCrlDistributionPoint(sut.toX509(dummyCertificateNoCrlExtension));

        // then
        Assertions.assertTrue(result.isEmpty());
    }

    @Test
    void getPathToCrlDistributionPoint_dummyCert_withEmptyCrlPath() {
        // when
        Optional<String> result = sut.getPathToCrlDistributionPoint(sut.toX509(dummyCertificateEmptyCrlPath));

        // then
        Assertions.assertTrue(result.isPresent());
        Assertions.assertEquals("", result.get());
    }
}
