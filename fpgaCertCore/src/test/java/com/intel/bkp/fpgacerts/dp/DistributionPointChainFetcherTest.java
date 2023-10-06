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

package com.intel.bkp.fpgacerts.dp;

import com.intel.bkp.crypto.x509.utils.AuthorityInformationAccessUtils;
import com.intel.bkp.crypto.x509.utils.X509CertificateUtils;
import com.intel.bkp.fpgacerts.chain.DistributionPointCertificate;
import com.intel.bkp.fpgacerts.exceptions.ChainFetchingException;
import com.intel.bkp.fpgacerts.exceptions.DataPathException;
import com.intel.bkp.fpgacerts.utils.X509UtilsWrapper;
import org.apache.commons.lang3.RandomUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DistributionPointChainFetcherTest {

    private static final String SUBJECT = "CN=some common name";
    private static final String ATTESTATION_CERT_URL = "https://localhost/attestation_cert_url";
    private static final String PARENT_CERT_URL = "https://localhost/parent_cert_url";
    private static final String ROOT_CERT_URL = "https://localhost/root_cert_url";

    private static MockedStatic<X509CertificateUtils> x509CertificateUtilsMockStatic;
    private static MockedStatic<X509UtilsWrapper> x509UtilsWrapperMockStatic;
    private static MockedStatic<AuthorityInformationAccessUtils> aiaUtilsMockStatic;

    @Mock
    private X509Certificate attestationCert;

    @Mock
    private X509Certificate parentCert;

    @Mock
    private X509Certificate rootCert;

    @Mock
    private DistributionPointConnector connector;

    @InjectMocks
    private DistributionPointChainFetcher sut;

    @BeforeAll
    public static void prepareStaticMock() {
        aiaUtilsMockStatic = mockStatic(AuthorityInformationAccessUtils.class);
        x509CertificateUtilsMockStatic = mockStatic(X509CertificateUtils.class);
        x509UtilsWrapperMockStatic = mockStatic(X509UtilsWrapper.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        aiaUtilsMockStatic.close();
        x509CertificateUtilsMockStatic.close();
        x509UtilsWrapperMockStatic.close();
    }

    @Test
    void downloadCertificateChainAsX509_blankUrl_ReturnsEmptyList() {
        // when
        final var result = sut.downloadCertificateChainAsX509(" ");

        // then
        assertTrue(result.isEmpty());
    }

    @Test
    void downloadCertificateChainAsX509_NullUrl_ReturnsEmptyList() {
        // when
        final var result = sut.downloadCertificateChainAsX509(null);

        // then
        assertTrue(result.isEmpty());
    }

    @Test
    void downloadCertificateChainAsX509_NonExistentUrl_Throws() {
        // given
        final String nonExistentUrl = "some not existent url";

        // when-then
        final var exception = assertThrows(DataPathException.class,
            () -> sut.downloadCertificateChainAsX509(nonExistentUrl));

        // then
        assertTrue(exception.getMessage().contains(nonExistentUrl));
    }

    @Test
    void downloadCertificateChainAsX509_FullChainToRoot_ReturnsCorrectList() {
        // given
        mockCertificateDownload(ATTESTATION_CERT_URL, attestationCert);
        mockIssuerUrl(attestationCert, PARENT_CERT_URL);
        mockCertificateDownload(PARENT_CERT_URL, parentCert);
        mockIssuerUrl(parentCert, ROOT_CERT_URL);
        mockCertificateDownload(ROOT_CERT_URL, rootCert);
        mockNoIssuerUrl(rootCert);
        mockAsSelfSigned(rootCert);

        // when
        final var result = sut.downloadCertificateChainAsX509(ATTESTATION_CERT_URL);

        // then
        assertIterableEquals(List.of(attestationCert, parentCert, rootCert), result);
    }

    @Test
    void downloadCertificateChainAsX509_NotFullChain_Throws() {
        // given
        mockCertificateDownload(ATTESTATION_CERT_URL, attestationCert);
        mockIssuerUrl(attestationCert, PARENT_CERT_URL);
        mockCertificateDownload(PARENT_CERT_URL, parentCert);
        mockNoIssuerUrl(parentCert);
        mockSubject(parentCert);

        // when-then
        final var exception = assertThrows(ChainFetchingException.class,
            () -> sut.downloadCertificateChainAsX509(ATTESTATION_CERT_URL));

        // then
        assertTrue(exception.getMessage().contains(SUBJECT));
    }

    @Test
    void downloadCertificateChain_FullChainToRoot_ReturnsCorrectList() {
        // given
        final var dpAttestationCert = new DistributionPointCertificate(ATTESTATION_CERT_URL, attestationCert);
        final var dpParentCert = new DistributionPointCertificate(PARENT_CERT_URL, parentCert);
        final var dpRootCert = new DistributionPointCertificate(ROOT_CERT_URL, rootCert);
        mockIssuerUrl(attestationCert, PARENT_CERT_URL);
        mockCertificateDownload(PARENT_CERT_URL, parentCert);
        mockIssuerUrl(parentCert, ROOT_CERT_URL);
        mockCertificateDownload(ROOT_CERT_URL, rootCert);
        mockNoIssuerUrl(rootCert);
        mockAsSelfSigned(rootCert);

        // when
        final var result = sut.downloadCertificateChain(dpAttestationCert);

        // then
        assertIterableEquals(List.of(dpAttestationCert, dpParentCert, dpRootCert), result);
    }

    private void mockCertificateDownload(String url, X509Certificate cert) {
        final var certBytes = RandomUtils.nextBytes(5);
        when(connector.tryGetBytes(url)).thenReturn(Optional.of(certBytes));
        when(X509UtilsWrapper.toX509(certBytes)).thenReturn(cert);
    }

    private void mockAsSelfSigned(X509Certificate cert) {
        when(X509CertificateUtils.isSelfSigned(cert)).thenReturn(true);
    }

    private void mockIssuerUrl(X509Certificate cert, String issuerUrl) {
        when(AuthorityInformationAccessUtils.getIssuerCertUrl(cert)).thenReturn(Optional.of(issuerUrl));
    }

    private void mockNoIssuerUrl(X509Certificate cert) {
        when(AuthorityInformationAccessUtils.getIssuerCertUrl(cert)).thenReturn(Optional.empty());
    }

    private void mockSubject(X509Certificate cert) {
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal(SUBJECT));
    }

}
