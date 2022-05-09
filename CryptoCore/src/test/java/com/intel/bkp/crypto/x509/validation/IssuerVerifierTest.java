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
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;

@ExtendWith(MockitoExtension.class)
class IssuerVerifierTest {

    // https://tsci.intel.com/content/IPCS/certs/attestation_5ADF841DDEAD944E_00000002.cer
    private static final String ATTESTATION_CERT_FILENAME = "attestation_5ADF841DDEAD944E_00000002.cer";
    // https://tsci.intel.com/content/IPCS/certs/IPCSSigningCA.cer
    private static final String PARENT_CERT_FILENAME = "IPCSSigningCA.cer";
    // https://tsci.intel.com/content/IPCS/certs/IPCS.cer
    private static final String ROOT_CERT_FILENAME = "IPCS.cer";

    private static X509Certificate attestationCert;
    private static X509Certificate parentCert;
    private static X509Certificate rootCert;

    private final IssuerVerifier sut = new IssuerVerifier();

    @BeforeAll
    static void init() throws Exception {
        attestationCert = TestUtil.loadCertificate(ATTESTATION_CERT_FILENAME);
        parentCert = TestUtil.loadCertificate(PARENT_CERT_FILENAME);
        rootCert = TestUtil.loadCertificate(ROOT_CERT_FILENAME);
    }

    @Test
    void verify_MatchingIssuer_ReturnsTrue() {
        // when-then
        Assertions.assertTrue(sut.verify(attestationCert, parentCert));
    }

    @Test
    void verify_MismatchedIssuer_ReturnsFalse() {
        // when-then
        Assertions.assertFalse(sut.verify(attestationCert, rootCert));
    }

}
