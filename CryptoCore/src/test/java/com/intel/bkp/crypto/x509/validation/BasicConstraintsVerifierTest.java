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

import com.intel.bkp.crypto.LogUtils;
import com.intel.bkp.crypto.TestUtil;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.org.lidalia.slf4jext.Level;

import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.stream.Stream;

import static com.intel.bkp.crypto.x509.validation.BasicConstraintsVerifier.CA_FALSE;
import static com.intel.bkp.crypto.x509.validation.BasicConstraintsVerifier.CA_TRUE_PATHLENGTH_NONE;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BasicConstraintsVerifierTest {

    /* Below cert was generated using OpenSSL with command:
    openssl req -newkey rsa:2048 -nodes -keyout test.pem -x509 -days 365 -out cert.pem
    The fact if cert contains BasicConstraints extension depends on content of openssl.cnf
    */
    private static final String CERT_WITHOUT_BASIC_CONSTRAINTS_FILENAME = "certWithoutBasicConstraints.pem";

    private static X509Certificate certWithoutBasicConstraints;

    @Mock
    X509Certificate certificate;

    private final BasicConstraintsVerifier sut = new BasicConstraintsVerifier();

    @BeforeAll
    static void init() throws Exception {
        certWithoutBasicConstraints = TestUtil.loadCertificate(CERT_WITHOUT_BASIC_CONSTRAINTS_FILENAME);
    }

    @AfterEach
    void clearLogs() {
        LogUtils.clearLogs(sut.getClass());
    }

    @Test
    void verify_CertHasNoBasicConstraints_ReturnsFalse() {
        // when-then
        verify_ReturnsFalseAndLogsErrorMessage(certWithoutBasicConstraints, "missing BasicConstraints");
    }

    @Test
    void verify_CertHasExpectedBasicConstraints_NonCriticalExtension_ReturnsTrue() {
        // given
        mockCertificate(CA_FALSE, false);

        // when-then
        Assertions.assertTrue(sut.verify(certificate, CA_FALSE));
    }

    @Test
    void verify_CertHasExpectedBasicConstraints_CriticalExtension_ReturnsTrue() {
        // given
        mockCertificate(CA_FALSE, true);

        // when-then
        Assertions.assertTrue(sut.verify(certificate, CA_FALSE));
    }

    @Test
    void verify_CertHasSufficientBasicConstraintsWithPathLengthLargerThanExpected_CriticalExtension_ReturnsTrue() {
        // given
        mockCertificate(3, true);

        // when-then
        Assertions.assertTrue(sut.verify(certificate, 2));
    }

    @Test
    void verify_CertHasSufficientBasicConstraintsWithUnlimitedPathLength_CriticalExtension_ReturnsTrue() {
        // given
        mockCertificate(CA_TRUE_PATHLENGTH_NONE, true);

        // when-then
        Assertions.assertTrue(sut.verify(certificate, 2));
    }

    @Test
    void verify_CertHasUnexpectedCaFalse_ReturnsFalse() {
        // given
        mockCertificate(CA_FALSE, false);

        // when-then
        verify_ReturnsFalseAndLogsErrorMessage(certificate, "CA=false");
    }

    @Test
    void verify_CertHasUnexpectedCaTrueWithNotSufficientPathlength_ReturnsFalse() {
        // given
        mockCertificate(3, false);

        // when-then
        verify_ReturnsFalseAndLogsErrorMessage(certificate, "CA=true, pathlength=3");
    }

    @Test
    void verify_CertHasUnexpectedCaTrueWithPathlengthSet_ReturnsFalse() {
        // given
        mockCertificate(0, false);

        // when-then
        verify_ReturnsFalseAndLogsErrorMessage(certificate, "CA=true, pathlength=0");
    }

    @Test
    void verify_CertHasUnrecognizedBasicConstraints_ReturnsFalse() {
        // given
        mockCertificate(-5, false);

        // when-then
        verify_ReturnsFalseAndLogsErrorMessage(certificate, "-5");
    }

    private void mockCertificate(int basicConstraintsValue, boolean isCritical) {
        final Set<String> setWithBasicConstraints = Set.of(Extension.basicConstraints.getId());
        final Set<String> emptySet = Set.of();
        when(certificate.getBasicConstraints()).thenReturn(basicConstraintsValue);
        when(certificate.getCriticalExtensionOIDs()).thenReturn(isCritical ? setWithBasicConstraints : emptySet);
        when(certificate.getNonCriticalExtensionOIDs()).thenReturn(isCritical ? emptySet : setWithBasicConstraints);
    }

    private void verify_ReturnsFalseAndLogsErrorMessage(X509Certificate certificate, String expectedMessagePart) {
        Assertions.assertFalse(sut.verify(certificate, 5));
        Assertions.assertTrue(getErrorLogs().anyMatch(message -> message.contains(expectedMessagePart)));
    }

    private Stream<String> getErrorLogs() {
        return LogUtils.getLogs(sut.getClass(), Level.ERROR);
    }
}
