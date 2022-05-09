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
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.List;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SubjectKeyIdentifierVerifierTest {

    private static final String FIRMWARE_CERT = "firmware_certificate.der";

    private static X509Certificate firmwareCert;

    @Mock
    private X509Certificate certificate;

    private SubjectKeyIdentifierVerifier sut = new SubjectKeyIdentifierVerifier();

    @BeforeAll
    static void init() throws Exception {
        firmwareCert = TestUtil.loadCertificate(FIRMWARE_CERT);
    }

    @Test
    void verify_WithOneCert_NoSKI_ReturnsTrue() {
        // given
        mockCertificateHasNoSKI();

        // when
        final boolean valid = sut.certificates(List.of(certificate)).verify();

        // then
        Assertions.assertTrue(valid);
    }

    @Test
    void verify_WithOneCert_CorrectSKI_ReturnsTrue() {
        // when
        final boolean valid = sut.certificates(List.of(firmwareCert)).verify();

        // then
        Assertions.assertTrue(valid);
    }

    @Test
    void verify_WithOneCert_IncorrectSKI_ReturnsFalse() {
        // given
        mockCertificateHasIncorrectSKI();

        // when
        final boolean valid = sut.certificates(List.of(certificate)).verify();

        // then
        Assertions.assertFalse(valid);
    }

    @Test
    void verify_WithMultipleCerts_OneCertContainsIncorrectSKI_ReturnsFalse() {
        // given
        mockCertificateHasIncorrectSKI();

        // when
        final boolean valid = sut.certificates(List.of(certificate, firmwareCert)).verify();

        // then
        Assertions.assertFalse(valid);
    }

    @Test
    void verify_WithMultipleCerts_AllCertsContainCorrectSKIOrNoExtension_ReturnsTrue() {
        // given
        mockCertificateHasNoSKI();

        // when
        final boolean valid = sut.certificates(List.of(certificate, firmwareCert)).verify();

        // then
        Assertions.assertTrue(valid);
    }

    private void mockCertificateHasNoSKI() {
        when(certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId())).thenReturn(null);
    }

    private void mockCertificateHasIncorrectSKI() {
        final var skiFromExtension = "0102030405060708091011121314151617181920";
        final var skiExtensionValue = fromHex("0416" + "0414" + skiFromExtension);
        when(certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId())).thenReturn(skiExtensionValue);
        when(certificate.getPublicKey()).thenReturn(firmwareCert.getPublicKey());
    }
}
