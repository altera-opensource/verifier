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

package com.intel.bkp.verifier.service.certificate;

import com.intel.bkp.ext.crypto.pem.PemFormatHeader;
import com.intel.bkp.verifier.Utils;
import com.intel.bkp.verifier.dp.DistributionPointConnector;
import com.intel.bkp.verifier.dp.ProxyCallbackFactory;
import com.intel.bkp.verifier.exceptions.SigmaException;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import com.intel.bkp.verifier.x509.X509CrlParentVerifier;
import com.intel.bkp.verifier.x509.X509CrlParser;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.mockito.Spy;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedList;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;

public class CrlVerifierTestWithRealCertificates {

    private static final String TEST_FOLDER = "certs/";
    private static final String DUMMY_CHAIN_FOLDER = "dummyChain/";

    private static byte[] intermediateCrl;
    private static byte[] rootCrl;
    private static String leafCert;
    private static String intermediateCertRevoked;
    private static String rootCert;

    private DistributionPointConnector connector = new DistributionPointConnector();
    private X509CertificateParser x509CertificateParser = new X509CertificateParser();
    @Spy
    private DistributionPointConnector connectorSpy = Mockito.spy(connector);

    @InjectMocks
    private CrlVerifier sut = new CrlVerifier(connectorSpy, new X509CrlParser(), x509CertificateParser,
        new X509CrlParentVerifier(), new ProxyCallbackFactory(), new ArrayList<>(), true);

    @BeforeAll
    static void init() throws Exception {
        // certificate chain generated based on tutorial https://pki-tutorial.readthedocs.io/en/latest/advanced/
        intermediateCrl = getBytesFromFile("intermediate-ca.crl");
        rootCrl = getBytesFromFile("root-ca.crl");
        leafCert = getPemFromFile("leaf-not-revoked.crt");
        intermediateCertRevoked = getPemFromFile("intermediate-ca-revoked.crt");
        rootCert = getPemFromFile("root-ca.crt");
    }

    private static byte[] getBytesFromFile(String filename) throws Exception {
        return Utils.readFromResources(TEST_FOLDER + DUMMY_CHAIN_FOLDER, filename);
    }

    private static String getPemFromFile(String filename) throws Exception {
        return new String(getBytesFromFile(filename), StandardCharsets.UTF_8);
    }

    @Test
    void verify_WithRevokedIntermediate_Throws() {
        // given
        Mockito.doReturn(intermediateCrl, rootCrl).when(connectorSpy).getBytes(any());
        final LinkedList<X509Certificate> list = new LinkedList<>();
        list.add(getCertFromPem(leafCert));
        list.add(getCertFromPem(intermediateCertRevoked));
        list.add(getCertFromPem(rootCert));

        // when-then
        SigmaException thrown = Assertions.assertThrows(SigmaException.class,
            () -> sut.certificates(list).verify());
        assertTrue(thrown.getMessage().contains("Intermediate certificate with serial number 2 is revoked."));

    }

    public X509Certificate getCertFromPem(String pem) {
        String pemWithoutMetadata = StringUtils.substringBetween(pem, PemFormatHeader.CERTIFICATE.getBegin(),
            PemFormatHeader.CERTIFICATE.getEnd());
        byte[] decoded = Base64.getDecoder().decode(pemWithoutMetadata.replace("\n", ""));

        return x509CertificateParser.toX509(decoded);
    }
}
