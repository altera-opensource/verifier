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

import com.intel.bkp.verifier.Utils;
import com.intel.bkp.verifier.exceptions.SigmaException;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import com.intel.bkp.verifier.x509.X509CrlParentVerifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import static com.intel.bkp.ext.crypto.x509.X509CertificateParser.toX509Certificate;
import static com.intel.bkp.ext.crypto.x509.X509CrlParser.toX509Crl;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class CrlVerifierTestWithRealCertificates {

    private static final String TEST_FOLDER = "certs/";
    private static final String DUMMY_CHAIN_FOLDER = "dummyChain/";

    private static X509CRL intermediateCrl;
    private static X509CRL rootCrl;
    private static X509Certificate leafCert;
    private static X509Certificate intermediateCertRevoked;
    private static X509Certificate rootCert;

    @Mock
    private ICrlProvider crlProvider;

    private CrlVerifier sut;

    @BeforeAll
    static void init() throws Exception {
        // certificate chain generated based on tutorial https://pki-tutorial.readthedocs.io/en/latest/advanced/
        intermediateCrl = getCrlFromFile("intermediate-ca.crl");
        rootCrl = getCrlFromFile("root-ca.crl");
        leafCert = getCertFromFile("leaf-not-revoked.crt");
        intermediateCertRevoked = getCertFromFile("intermediate-ca-revoked.crt");
        rootCert = getCertFromFile("root-ca.crt");
    }

    @BeforeEach
    void prepareSut() {
        sut = new CrlVerifier(new X509CertificateParser(), new X509CrlParentVerifier(), crlProvider);
    }

    private static X509CRL getCrlFromFile(String filename) throws Exception {
        return toX509Crl(getBytesFromFile(filename));
    }

    private static X509Certificate getCertFromFile(String filename) throws Exception {
        return toX509Certificate(getBytesFromFile(filename));
    }

    private static byte[] getBytesFromFile(String filename) throws Exception {
        return Utils.readFromResources(TEST_FOLDER + DUMMY_CHAIN_FOLDER, filename);
    }

    @Test
    void verify_WithRevokedIntermediate_Throws() {
        // given
        when(crlProvider.getCrl(any())).thenReturn(intermediateCrl, rootCrl);
        final LinkedList<X509Certificate> list = new LinkedList<>();
        list.add(leafCert);
        list.add(intermediateCertRevoked);
        list.add(rootCert);

        // when-then
        SigmaException thrown = Assertions.assertThrows(SigmaException.class,
            () -> sut.certificates(list).verify());
        assertTrue(thrown.getMessage().contains("Intermediate certificate with serial number 2 is revoked."));

    }
}
