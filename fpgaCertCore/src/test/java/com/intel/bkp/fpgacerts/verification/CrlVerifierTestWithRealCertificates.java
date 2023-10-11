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

package com.intel.bkp.fpgacerts.verification;

import com.intel.bkp.crypto.x509.validation.SignatureVerifier;
import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509Certificate;
import static com.intel.bkp.crypto.x509.parsing.X509CrlParser.toX509Crl;
import static com.intel.bkp.test.FileUtils.readFromResources;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
        intermediateCrl = toX509Crl(readFromResources(TEST_FOLDER + DUMMY_CHAIN_FOLDER,
            "intermediate-ca.crl"));
        rootCrl = toX509Crl(readFromResources(TEST_FOLDER + DUMMY_CHAIN_FOLDER,
            "root-ca.crl"));
        leafCert = toX509Certificate(readFromResources(TEST_FOLDER + DUMMY_CHAIN_FOLDER,
            "leaf-not-revoked.crt"));
        intermediateCertRevoked =
            toX509Certificate(readFromResources(TEST_FOLDER + DUMMY_CHAIN_FOLDER,
                "intermediate-ca-revoked.crt"));
        rootCert = toX509Certificate(readFromResources(TEST_FOLDER + DUMMY_CHAIN_FOLDER,
            "root-ca.crt"));
    }

    @BeforeEach
    void prepareSut() {
        sut = new CrlVerifier(new SignatureVerifier(), crlProvider);
    }

    @Test
    void verify_WithRevokedIntermediate_ReturnsFalse() {
        // given
        when(crlProvider.getCrl(any())).thenReturn(intermediateCrl, rootCrl);
        final List<X509Certificate> list = new LinkedList<>();
        list.add(leafCert);
        list.add(intermediateCertRevoked);
        list.add(rootCert);

        // when
        final boolean result = sut.certificates(list).verify();

        // then
        assertFalse(result);
    }
}
