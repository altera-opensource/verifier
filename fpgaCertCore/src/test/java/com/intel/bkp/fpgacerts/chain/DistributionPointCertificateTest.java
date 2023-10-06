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

package com.intel.bkp.fpgacerts.chain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class DistributionPointCertificateTest {

    private static final String URL_1 = "first URL";
    private static final String URL_2 = "second URL";

    @Mock
    private X509Certificate cert_1;

    @Mock
    private X509Certificate cert_2;

    private Collection<DistributionPointCertificate> dpCerts;

    @BeforeEach
    void initCollection() {
        dpCerts = List.of(new DistributionPointCertificate(URL_1, cert_1),
            new DistributionPointCertificate(URL_2, cert_2));
    }

    @Test
    void getX509Certificates_Success() {
        // given
        final var x509Certs = List.of(cert_1, cert_2);

        // when
        final var result = DistributionPointCertificate.getX509Certificates(dpCerts);

        // then
        assertIterableEquals(x509Certs, result);
    }

    @Test
    void getX509Certificates_EmptyCollection_ReturnsEmptyList() {
        // when
        final var result = DistributionPointCertificate.getX509Certificates(List.of());

        // then
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void getX509Certificates_NullCollection_ThrowsNullPointer() {
        // when-then
        assertThrows(NullPointerException.class,
            () -> DistributionPointCertificate.getX509Certificates(null));
    }
}
