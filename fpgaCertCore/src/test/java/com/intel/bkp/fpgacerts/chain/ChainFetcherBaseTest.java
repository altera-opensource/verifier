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

package com.intel.bkp.fpgacerts.chain;

import com.intel.bkp.crypto.x509.utils.AuthorityInformationAccessUtils;
import com.intel.bkp.crypto.x509.utils.X509CertificateUtils;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ChainFetcherBaseTest {

    @RequiredArgsConstructor
    private static class CertificateFetcherTestImpl implements ICertificateFetcher {

        private final Map<String, X509Certificate> certMap;

        @Override
        public Optional<X509Certificate> fetchCertificate(String url) {
            return certMap.containsKey(url)
                   ? Optional.of(certMap.get(url))
                   : Optional.empty();
        }
    }

    private static class ChainFetcherTestImpl extends ChainFetcherBase {

        protected ChainFetcherTestImpl(Map<String, X509Certificate> certMap) {
            super(new CertificateFetcherTestImpl(certMap));
        }

        @Override
        protected RuntimeException getFetchingFailureException(String url) {
            return new RuntimeException(url);
        }

        @Override
        protected RuntimeException getNoIssuerCertUrlException(String certificateSubject) {
            return new RuntimeException(certificateSubject);
        }
    }

    private static final String CHILD_URL = "child url";
    private static final String INTERMEDIATE_URL = "intermediate url";
    private static final String ROOT_URL = "root url";
    private static final String SUBJECT = "CN=some common name";

    private static MockedStatic<AuthorityInformationAccessUtils> aiaUtilsMockStatic;
    private static MockedStatic<X509CertificateUtils> x509CertificateUtilsMockStatic;

    @Mock
    private X509Certificate child;

    @Mock
    private X509Certificate intermediate;

    @Mock
    private X509Certificate root;

    private List<DistributionPointCertificate> correctChain;

    @BeforeAll
    public static void prepareStaticMock() {
        x509CertificateUtilsMockStatic = mockStatic(X509CertificateUtils.class);
        aiaUtilsMockStatic = mockStatic(AuthorityInformationAccessUtils.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        x509CertificateUtilsMockStatic.close();
        aiaUtilsMockStatic.close();
    }

    @BeforeEach
    void prepareSut() {
        final var certMap = Map.of(
            CHILD_URL, child,
            INTERMEDIATE_URL, intermediate,
            ROOT_URL, root
        );
        sut = new ChainFetcherTestImpl(certMap);

        correctChain = List.of(
            new DistributionPointCertificate(CHILD_URL, child),
            new DistributionPointCertificate(INTERMEDIATE_URL, intermediate),
            new DistributionPointCertificate(ROOT_URL, root));
    }


    private ChainFetcherTestImpl sut;

    @Test
    void fetchCertificateChain_blankUrl_ReturnsEmptyList() {
        // when
        final var result = sut.fetchCertificateChain(" ");

        // then
        Assertions.assertTrue(result.isEmpty());
    }

    @Test
    void fetchCertificateChain_NullUrl_ReturnsEmptyList() {
        // when
        final var result = sut.fetchCertificateChain((String) null);

        // then
        Assertions.assertTrue(result.isEmpty());
    }

    @Test
    void fetchCertificateChain_NullCert_ReturnsEmptyList() {
        // when
        final var result = sut.fetchCertificateChain((X509Certificate) null);

        // then
        Assertions.assertTrue(result.isEmpty());
    }

    @Test
    void fetchCertificateChain_NonExistentUrl_Throws() {
        // given
        final String nonExistentUrl = "some not existent url";

        // when-then
        final var exception = Assertions.assertThrows(RuntimeException.class,
            () -> sut.fetchCertificateChain(nonExistentUrl));

        // then
        Assertions.assertTrue(exception.getMessage().contains(nonExistentUrl));
    }

    @Test
    void fetchCertificateChain_FullChainWithRootWithoutAki_ReturnsCorrectList() {
        // given
        mockIssuerUrl(child, INTERMEDIATE_URL);
        mockIssuerUrl(intermediate, ROOT_URL);
        mockNoIssuerUrl(root);
        mockAsSelfSigned(root);

        // when
        final var result = sut.fetchCertificateChain(CHILD_URL);

        // then
        Assertions.assertIterableEquals(correctChain, result);
    }

    @Test
    void fetchCertificateChain_FullChainWithRootWithAki_DoesNotRunInfinitely() {
        // given
        mockIssuerUrl(child, INTERMEDIATE_URL);
        mockIssuerUrl(intermediate, ROOT_URL);
        mockIssuerUrl(root, ROOT_URL);
        mockAsSelfSigned(root);

        // when
        final var result = sut.fetchCertificateChain(CHILD_URL);

        // then
        Assertions.assertIterableEquals(correctChain, result);
    }

    @Test
    void fetchCertificateChain_StartingFromChildCert_ReturnsCorrectListFromIntermediateCert() {
        // given
        mockIssuerUrl(child, INTERMEDIATE_URL);
        mockIssuerUrl(intermediate, ROOT_URL);
        mockNoIssuerUrl(root);
        mockAsSelfSigned(root);
        final var chainFromIntermediate = correctChain.stream().skip(1).collect(Collectors.toList());

        // when
        final var result = sut.fetchCertificateChain(child);

        // then
        Assertions.assertIterableEquals(chainFromIntermediate, result);
    }

    @Test
    void fetchCertificateChain_ChildWithoutAki_Throws() {
        // given
        mockSubject(child);
        mockNoIssuerUrl(child);

        // when-then
        final var exception = Assertions.assertThrows(RuntimeException.class,
            () -> sut.fetchCertificateChain(CHILD_URL));

        // then
        Assertions.assertTrue(exception.getMessage().contains(SUBJECT));
    }

    @Test
    void fetchCertificateChain_IntermediateWithoutAki_Throws() {
        // given
        mockSubject(intermediate);
        mockIssuerUrl(child, INTERMEDIATE_URL);
        mockNoIssuerUrl(intermediate);

        // when-then
        final var exception = Assertions.assertThrows(RuntimeException.class,
            () -> sut.fetchCertificateChain(CHILD_URL));

        // then
        Assertions.assertTrue(exception.getMessage().contains(SUBJECT));
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
