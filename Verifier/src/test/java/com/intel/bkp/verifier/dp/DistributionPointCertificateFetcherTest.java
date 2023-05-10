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

package com.intel.bkp.verifier.dp;

import com.intel.bkp.verifier.exceptions.X509ParsingException;
import com.intel.bkp.verifier.x509.X509UtilsWrapper;
import org.apache.commons.lang3.RandomUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DistributionPointCertificateFetcherTest {

    private static final String URL = "URL";

    private static MockedStatic<X509UtilsWrapper> x509UtilsWrapperMockStatic;

    @Mock
    private X509Certificate cert;

    @Mock
    private DistributionPointConnector connector;

    @InjectMocks
    private DistributionPointCertificateFetcher sut;

    @BeforeAll
    public static void prepareStaticMock() {
        x509UtilsWrapperMockStatic = mockStatic(X509UtilsWrapper.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        x509UtilsWrapperMockStatic.close();
    }

    @Test
    void fetchCertificate_Success() {
        // given
        mockCertificateDownload(URL, cert);

        // when
        final Optional<X509Certificate> result = sut.fetchCertificate(URL);

        // then
        Assertions.assertTrue(result.isPresent());
        Assertions.assertEquals(result.get(), cert);
    }

    @Test
    void fetchCertificate_downloadFailure_ReturnsEmptyOptional() {
        // given
        when(connector.tryGetBytes(URL)).thenReturn(Optional.empty());

        // when
        final Optional<X509Certificate> result = sut.fetchCertificate(URL);

        // then
        Assertions.assertTrue(result.isEmpty());
    }

    @Test
    void fetchCertificate_parsingFailure_Throws() {
        // given
        final byte[] certBytes = new byte[]{1, 2, 3};
        when(connector.tryGetBytes(URL)).thenReturn(Optional.of(certBytes));
        when(X509UtilsWrapper.toX509(certBytes)).thenThrow(new X509ParsingException(null));

        // when-then
        Assertions.assertThrows(X509ParsingException.class, () -> sut.fetchCertificate(URL));
    }

    private void mockCertificateDownload(String url, X509Certificate cert) {
        final var certBytes = RandomUtils.nextBytes(5);
        when(connector.tryGetBytes(url)).thenReturn(Optional.of(certBytes));
        when(X509UtilsWrapper.toX509(certBytes)).thenReturn(cert);
    }

}
