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

package com.intel.bkp.crypto.x509.validation;

import com.intel.bkp.test.FileUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
public class KeyUsageVerifierTest {

    // openssl req -newkey rsa:2048 -nodes -keyout test.pem -x509 -days 365 -out CA.pem
    private static final String INVALID_CERT = "CA.pem";
    // https://tsci.intel.com/content/IPCS/certs/attestation_5ADF841DDEAD944E_00000002.cer
    private static final String VALID_CERT = "attestation_5ADF841DDEAD944E_00000002.cer";

    private static X509Certificate invalidCert;
    private static X509Certificate validCert;

    @InjectMocks
    private KeyUsageVerifier sut;

    @BeforeAll
    static void init() throws Exception {
        invalidCert = FileUtils.loadCertificate(INVALID_CERT);
        validCert = FileUtils.loadCertificate(VALID_CERT);
    }

    @Test
    void verify_CertWithKeyUsageExtension_ContainsKeyUsage_ReturnsTrue() {
        // when-then
        assertTrue(sut.verify(validCert, KeyUsage.DIGITAL_SIGNATURE));
    }

    @Test
    void verify_CertWithKeyUsageExtension_DoesNotContainKeyUsage_ReturnsFalse() {
        // when-then
        assertFalse(sut.verify(validCert, KeyUsage.KEY_CERT_SIGN));
    }

    @Test
    void verify_CertWithoutKeyUsageExtension_ReturnsFalse() {
        // when-then
        assertFalse(sut.verify(invalidCert, KeyUsage.DIGITAL_SIGNATURE));
    }
}
