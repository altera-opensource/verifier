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
import com.intel.bkp.verifier.exceptions.CertificateChainValidationException;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.security.cert.X509Certificate;
import java.util.Set;

import static com.intel.bkp.verifier.x509.X509CertificateBasicConstraintsVerifier.CA_FALSE;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class X509CertificateBasicConstraintsVerifierTest {

    private static final String TEST_FOLDER = "certs/";
    /* Below cert was generated using OpenSSL with command:
    openssl req -newkey rsa:2048 -nodes -keyout test.pem -x509 -days 365 -out cert.pem
    The fact if cert contains BasicConstraints extension depends on content of openssl.cnf
    */
    private static final String CERT_WITHOUT_BASIC_CONSTRAINTS_FILENAME = "certWithoutBasicConstraints.pem";
    private static final X509CertificateParser X509_PARSER = new X509CertificateParser();

    private static X509Certificate certWithoutBasicConstraints;

    @Mock
    X509Certificate certificate;

    private X509CertificateBasicConstraintsVerifier sut = new X509CertificateBasicConstraintsVerifier();

    @BeforeAll
    static void init() throws Exception {
        certWithoutBasicConstraints = X509_PARSER.toX509(Utils.readFromResources(TEST_FOLDER,
            CERT_WITHOUT_BASIC_CONSTRAINTS_FILENAME));
    }

    @Test
    void verify_CertHasNoBasicConstraints_Throws() {
        // when-then
        verify_ThrowsExceptionWithMessage(certWithoutBasicConstraints, "missing BasicConstraints");
    }

    @Test
    void verify_CertHasExpectedBasicConstraints_NonCriticalExtension_DoesNotThrow() {
        // given
        mockCertificate(CA_FALSE, false);

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.verify(certificate, CA_FALSE));
    }

    @Test
    void verify_CertHasExpectedBasicConstraints_CriticalExtension_DoesNotThrow() {
        // given
        mockCertificate(CA_FALSE, true);

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.verify(certificate, CA_FALSE));
    }

    @Test
    void verify_CertHasSufficientBasicConstraintsWithPathLengthLargerThanExpected_CriticalExtension_DoesNotThrow() {
        // given
        mockCertificate(3, true);

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.verify(certificate, 2));
    }

    @Test
    void verify_CertHasUnexpectedCaFalse_Throws() {
        // given
        mockCertificate(CA_FALSE, false);

        // when-then
        verify_ThrowsExceptionWithMessage(certificate, "CA=false");
    }

    @Test
    void verify_CertHasUnexpectedCaTrueWithNotSufficientPathlength_Throws() {
        // given
        mockCertificate(3, false);

        // when-then
        verify_ThrowsExceptionWithMessage(certificate, "CA=true, pathlength=3");
    }

    @Test
    void verify_CertHasUnexpectedCaTrueWithPathlengthSet_Throws() {
        // given
        mockCertificate(0, false);

        // when-then
        verify_ThrowsExceptionWithMessage(certificate, "CA=true, pathlength=0");
    }

    @Test
    void verify_CertHasUnrecognizedBasicConstraints_Throws() {
        // given
        mockCertificate(-5, false);

        // when-then
        verify_ThrowsExceptionWithMessage(certificate, "-5");
    }

    private void mockCertificate(int basicConstraintsValue, boolean isCritical) {
        final Set<String> setWithBasicConstraints = Set.of(Extension.basicConstraints.getId());
        final Set<String> emptySet = Set.of();
        when(certificate.getBasicConstraints()).thenReturn(basicConstraintsValue);
        when(certificate.getCriticalExtensionOIDs()).thenReturn(isCritical ? setWithBasicConstraints : emptySet);
        when(certificate.getNonCriticalExtensionOIDs()).thenReturn(isCritical ? emptySet : setWithBasicConstraints);
    }

    private void verify_ThrowsExceptionWithMessage(X509Certificate certificate, String expectedMessagePart) {
        final CertificateChainValidationException ex =
            Assertions.assertThrows(CertificateChainValidationException.class,
                () -> sut.verify(certificate, 5));
        Assertions.assertTrue(ex.getMessage().contains(expectedMessagePart));
    }
}
