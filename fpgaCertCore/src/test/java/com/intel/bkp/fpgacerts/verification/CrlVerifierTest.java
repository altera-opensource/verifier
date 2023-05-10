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

import ch.qos.logback.classic.Level;
import com.intel.bkp.crypto.x509.utils.CrlDistributionPointsUtils;
import com.intel.bkp.crypto.x509.validation.SignatureVerifier;
import com.intel.bkp.fpgacerts.LoggerTestUtil;
import com.intel.bkp.fpgacerts.exceptions.CrlSignatureException;
import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import lombok.SneakyThrows;
import org.apache.commons.lang3.time.DateUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.ListIterator;
import java.util.Optional;
import java.util.Set;

import static com.intel.bkp.fpgacerts.verification.CrlVerifier.INVALID_NEXT_UPDATE_LOG_MSG;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CrlVerifierTest {

    private LoggerTestUtil loggerTestUtil;

    private static final BigInteger REVOKED_SERIAL_NUMBER = BigInteger.ONE;
    private static final BigInteger NOT_REVOKED_SERIAL_NUMBER = BigInteger.TWO;
    private static final String LEAF_CRL_PATH = "Leaf CRL URL";
    private static final String PARENT_CRL_PATH = "Parent CRL URL";

    private static MockedStatic<CrlDistributionPointsUtils> crlDistributionPointsUtilsMockStatic;

    @Mock
    private X509CRL leafCRL;

    @Mock
    private X509CRL parentCRL;

    @Mock
    private SignatureVerifier signatureVerifier;

    @Mock
    private ICrlProvider crlProvider;

    @Mock
    private List<X509Certificate> certificates;

    @Mock
    private X509Certificate leafCertificate;

    @Mock
    private X509Certificate parentCertificate;

    @Mock
    private X509Certificate rootCertificate;

    @Mock
    private ListIterator<X509Certificate> certificateChainIterator;

    @Mock
    private ListIterator<X509Certificate> leafCertIssuerCertsIterator;

    @Mock
    private ListIterator<X509Certificate> parentCertIssuerCertsIterator;

    @InjectMocks
    private CrlVerifier sut;

    @BeforeAll
    public static void prepareStaticMock() {
        crlDistributionPointsUtilsMockStatic = mockStatic(CrlDistributionPointsUtils.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        crlDistributionPointsUtilsMockStatic.close();
    }

    @BeforeEach
    void setUpClass() {
        sut.certificates(certificates);
        loggerTestUtil = LoggerTestUtil.instance(sut.getClass());
    }

    @AfterEach
    void clearLogs() {
        loggerTestUtil.reset();
    }

    @Test
    void verify_NotRevokedDevice_Success() {
        // given
        mockChainWith2Certs();
        mockLeafCrlOnDp();
        mockLeafCrlSignedByDirectParent();
        mockLeafCertIsNotRevoked();

        // when-then
        Assertions.assertTrue(() -> sut.verify());

        // then
        verify(signatureVerifier).verify(leafCRL, parentCertificate);
    }

    @Test
    void verify_WithRevokedDevice_ReturnFalse() {
        // given
        mockChainWith2Certs();
        mockLeafCrlOnDp();
        mockLeafCrlSignedByDirectParent();
        mockLeafCertIsRevoked();

        // when-then
        Assertions.assertFalse(() -> sut.verify());

        // then
        verify(signatureVerifier).verify(leafCRL, parentCertificate);
    }

    @Test
    void verify_WithRevokedIntermediateCert_ReturnsFalse() {
        // given
        mockChainWith3Certs();
        mockLeafCrlOnDp();
        mockLeafCrlSignedByDirectParent();
        mockParentCrlOnDp();
        mockParentCrlSignedByRoot();
        mockParentCertIsRevoked();

        // when-then
        Assertions.assertFalse(() -> sut.verify());
    }

    @Test
    void verify_CrlSignedNotByDirectCertIssuer_Success() {
        // given
        mockChainWith3Certs();
        mockLeafCrlOnDp();
        mockLeafCrlSignedByRoot();
        mockParentCrlOnDp();
        mockParentCrlSignedByRoot();

        // when-then
        Assertions.assertTrue(() -> sut.verify());

        // then
        verify(signatureVerifier).verify(leafCRL, parentCertificate);
        verify(signatureVerifier).verify(leafCRL, rootCertificate);
        verify(signatureVerifier).verify(parentCRL, rootCertificate);
    }

    @Test
    void verify_CrlNotSignedByAnyCertInChain_Throws() {
        // given
        mockChainWith3Certs();
        mockLeafCrlOnDp();
        mockLeafCrlNotSignedByAnyCertInChain();

        // when-then
        CrlSignatureException ex = Assertions.assertThrows(CrlSignatureException.class, () -> sut.verify());

        // then
        Assertions.assertEquals("Failed to verify signature of CRL", ex.getMessage());
        verify(signatureVerifier).verify(leafCRL, parentCertificate);
        verify(signatureVerifier).verify(leafCRL, rootCertificate);
    }

    @Test
    void verify_CrlWithoutNextUpdate_LogsWarning() {
        // given
        when(leafCRL.getNextUpdate()).thenReturn(null);
        mockChainWith2Certs();
        mockLeafCrlOnDp();
        mockLeafCrlSignedByDirectParent();
        mockLeafCertIsNotRevoked();

        // when-then
        Assertions.assertTrue(() -> sut.verify());

        // then
        Assertions.assertTrue(loggerTestUtil.contains(INVALID_NEXT_UPDATE_LOG_MSG, Level.WARN));
    }

    @Test
    void verify_CrlExpired_LogsWarning() {
        // given
        final Date yesterday = DateUtils.addDays(new Date(), -1);
        when(leafCRL.getNextUpdate()).thenReturn(yesterday);
        mockChainWith2Certs();
        mockLeafCrlOnDp();
        mockLeafCrlSignedByDirectParent();
        mockLeafCertIsNotRevoked();

        // when-then
        Assertions.assertTrue(() -> sut.verify());

        // then
        Assertions.assertTrue(loggerTestUtil.contains(INVALID_NEXT_UPDATE_LOG_MSG, Level.WARN));
    }

    @Test
    void verify_CrlNotExpired_DoesNotLogWarning() {
        // given
        final Date tomorrow = DateUtils.addDays(new Date(), 1);
        when(leafCRL.getNextUpdate()).thenReturn(tomorrow);
        mockChainWith2Certs();
        mockLeafCrlOnDp();
        mockLeafCrlSignedByDirectParent();
        mockLeafCertIsNotRevoked();

        // when-then
        Assertions.assertTrue(() -> sut.verify());

        // then
        Assertions.assertEquals(0, loggerTestUtil.getSize(Level.WARN));
    }

    @Test
    void verify_WithLeafCertWithoutCrlExtension_LeafCrlNotRequired_ReturnTrue() {
        // given
        mockChainWith3Certs();
        mockLeafCertDoesNotContainUrlToCrl();
        mockParentCrlOnDp();
        mockParentCrlSignedByRoot(false);

        // when-then
        Assertions.assertTrue(() -> sut.doNotRequireCrlForLeafCertificate().verify());

        // then
        verify(signatureVerifier).verify(parentCRL, rootCertificate);
        verifyNoMoreInteractions(signatureVerifier);
    }

    @Test
    void verify_WithIntermediateCertWithoutCrlExtension_LeafCrlNotRequired_ReturnFalse() {
        // given
        mockChainWith3Certs();
        mockLeafCertDoesNotContainUrlToCrl();
        mockIntermediateCertDoesNotContainUrlToCrl();

        // when-then
        Assertions.assertFalse(() -> sut.doNotRequireCrlForLeafCertificate().verify());

        // then
        verifyNoInteractions(signatureVerifier);
    }

    @Test
    void verify_WithLeafCertWithoutCrlExtension_LeafCrlRequired_ReturnFalse() {
        // given
        mockChainWith2Certs();
        mockLeafCertDoesNotContainUrlToCrl();

        // when-then
        Assertions.assertFalse(() -> sut.verify());

        // then
        verifyNoInteractions(signatureVerifier);
    }

    private void mockChainWith3Certs() {
        when(certificates.listIterator()).thenReturn(certificateChainIterator);
        when(certificateChainIterator.hasNext()).thenReturn(true, true, false);
        when(certificateChainIterator.next()).thenReturn(leafCertificate, parentCertificate, rootCertificate);
    }

    private void mockChainWith2Certs() {
        when(certificates.listIterator()).thenReturn(certificateChainIterator);
        when(certificateChainIterator.hasNext()).thenReturn(true, false);
        when(certificateChainIterator.next()).thenReturn(leafCertificate, parentCertificate);
    }

    @SneakyThrows
    private void mockLeafCrlOnDp() {
        when(CrlDistributionPointsUtils.getCrlUrl(leafCertificate)).thenReturn(Optional.of(LEAF_CRL_PATH));
        when(crlProvider.getCrl(LEAF_CRL_PATH)).thenReturn(leafCRL);
    }

    @SneakyThrows
    private void mockLeafCertDoesNotContainUrlToCrl() {
        when(CrlDistributionPointsUtils.getCrlUrl(leafCertificate)).thenReturn(Optional.empty());
    }

    @SneakyThrows
    private void mockIntermediateCertDoesNotContainUrlToCrl() {
        when(CrlDistributionPointsUtils.getCrlUrl(parentCertificate)).thenReturn(Optional.empty());
    }

    @SneakyThrows
    private void mockParentCrlOnDp() {
        when(CrlDistributionPointsUtils.getCrlUrl(parentCertificate)).thenReturn(Optional.of(PARENT_CRL_PATH));
        when(crlProvider.getCrl(PARENT_CRL_PATH)).thenReturn(parentCRL);
    }

    private void mockLeafCrlSignedByDirectParent() {
        when(certificateChainIterator.nextIndex()).thenReturn(1);
        when(certificates.listIterator(1)).thenReturn(leafCertIssuerCertsIterator);
        when(leafCertIssuerCertsIterator.hasNext()).thenReturn(true);
        when(leafCertIssuerCertsIterator.next()).thenReturn(parentCertificate);
        when(signatureVerifier.verify(leafCRL, parentCertificate)).thenReturn(true);
    }

    private void mockLeafCrlSignedByRoot() {
        when(certificateChainIterator.nextIndex()).thenReturn(1);
        when(certificates.listIterator(1)).thenReturn(leafCertIssuerCertsIterator);
        when(leafCertIssuerCertsIterator.hasNext()).thenReturn(true, true);
        when(leafCertIssuerCertsIterator.next()).thenReturn(parentCertificate, rootCertificate);
        when(signatureVerifier.verify(leafCRL, parentCertificate)).thenReturn(false);
        when(signatureVerifier.verify(leafCRL, rootCertificate)).thenReturn(true);
    }

    private void mockLeafCrlNotSignedByAnyCertInChain() {
        when(certificateChainIterator.nextIndex()).thenReturn(1);
        when(certificates.listIterator(1)).thenReturn(leafCertIssuerCertsIterator);
        when(leafCertIssuerCertsIterator.hasNext()).thenReturn(true, true, false);
        when(leafCertIssuerCertsIterator.next()).thenReturn(parentCertificate, rootCertificate);
        when(signatureVerifier.verify(leafCRL, parentCertificate)).thenReturn(false);
        when(signatureVerifier.verify(leafCRL, rootCertificate)).thenReturn(false);
    }

    private void mockParentCrlSignedByRoot() {
        mockParentCrlSignedByRoot(true);
    }

    private void mockParentCrlSignedByRoot(boolean leafCrlExists) {
        if (leafCrlExists) {
            when(certificateChainIterator.nextIndex()).thenReturn(1, 2);
        } else {
            when(certificateChainIterator.nextIndex()).thenReturn(2);
        }
        when(certificates.listIterator(2)).thenReturn(parentCertIssuerCertsIterator);
        when(parentCertIssuerCertsIterator.hasNext()).thenReturn(true, false);
        when(parentCertIssuerCertsIterator.next()).thenReturn(rootCertificate);
        when(signatureVerifier.verify(parentCRL, rootCertificate)).thenReturn(true);
    }

    private void mockLeafCertIsNotRevoked() {
        mockSerialNumber(leafCertificate, NOT_REVOKED_SERIAL_NUMBER);
        mockCrlWithRevokedEntry(leafCRL, REVOKED_SERIAL_NUMBER);
    }

    private void mockLeafCertIsRevoked() {
        mockSerialNumber(leafCertificate, REVOKED_SERIAL_NUMBER);
        mockCrlWithRevokedEntry(leafCRL, REVOKED_SERIAL_NUMBER);
    }

    private void mockParentCertIsRevoked() {
        mockSerialNumber(parentCertificate, REVOKED_SERIAL_NUMBER);
        mockCrlWithRevokedEntry(parentCRL, REVOKED_SERIAL_NUMBER);
    }

    private void mockSerialNumber(X509Certificate certificate, BigInteger serialNumber) {
        when(certificate.getSerialNumber()).thenReturn(serialNumber);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void mockCrlWithRevokedEntry(X509CRL crl, BigInteger revokedSerialNumber) {
        final X509CRLEntry crlEntry = mock(X509CRLEntry.class);
        when(crl.getRevokedCertificates()).thenReturn((Set) Set.of(crlEntry));
        when(crlEntry.getSerialNumber()).thenReturn(revokedSerialNumber);
    }
}
