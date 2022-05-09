/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2022 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.crypto.x509.validation;

import com.intel.bkp.crypto.TestUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

@ExtendWith(MockitoExtension.class)
class SignatureVerifierTest {

    // https://tsci.intel.com/content/IPCS/crls/IPCSSigningCA.crl
    private static final String CRL_FILENAME = "IPCSSigningCA.crl";
    // https://tsci.intel.com/content/IPCS/certs/IPCSSigningCA.cer
    private static final String CHILD_CERT_FILENAME = "IPCSSigningCA.cer";
    // https://tsci.intel.com/content/IPCS/certs/IPCS.cer
    private static final String PARENT_CERT_FILENAME = "IPCS.cer";

    private static X509CRL crl;
    private static X509Certificate childCert;
    private static X509Certificate parentCert;

    @InjectMocks
    private SignatureVerifier sut;

    @BeforeAll
    static void init() throws Exception {
        crl = TestUtil.loadCrl(CRL_FILENAME);
        childCert = TestUtil.loadCertificate(CHILD_CERT_FILENAME);
        parentCert = TestUtil.loadCertificate(PARENT_CERT_FILENAME);
    }

    @Test
    void verify_Cert_MatchingParent_ReturnsTrue() {
        // when-then
        Assertions.assertTrue(sut.verify(childCert, parentCert));
    }

    @Test
    void verify_Cert_InvalidParent_ReturnsFalse() {
        // when-then
        Assertions.assertFalse(sut.verify(parentCert, childCert));
    }

    @Test
    void verify_Crl_MatchingParent_ReturnsTrue() {
        // when
        Assertions.assertTrue(sut.verify(crl, childCert));
    }

    @Test
    void verify_Crl_InvalidParent_ReturnsFalse() {
        // when-then
        Assertions.assertFalse(sut.verify(crl, parentCert));
    }
}
