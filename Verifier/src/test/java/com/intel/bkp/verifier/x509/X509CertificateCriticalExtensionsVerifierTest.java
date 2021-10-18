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

import com.intel.bkp.verifier.exceptions.CertificateChainValidationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.Set;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class X509CertificateCriticalExtensionsVerifierTest {

    private static final String OID_1 = "1.2.3.1";
    private static final String OID_2 = "1.2.3.2";
    private static final String OID_3 = "1.2.3.3";

    @Mock
    private X509Certificate certificate;

    private X509CertificateCriticalExtensionsVerifier sut = new X509CertificateCriticalExtensionsVerifier();

    @Test
    void verify_NoCriticalOids_DoesNotThrow() {
        // given
        final var knownOids = Set.of(OID_1, OID_2);
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of());

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.verify(certificate, knownOids));
    }

    @Test
    void verify_AllCriticalOidsAreKnown_DoesNotThrow() {
        // given
        final var knownOids = Set.of(OID_1, OID_2, OID_3);
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(OID_1, OID_2));

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.verify(certificate, knownOids));
    }

    @Test
    void verify_CriticalOidIsUnrecognized_Throws() {
        // given
        final var knownOids = Set.of(OID_1, OID_2);
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(OID_3));

        // when-then
        final CertificateChainValidationException ex =
            Assertions.assertThrows(CertificateChainValidationException.class,
                () -> sut.verify(certificate, knownOids));
        Assertions.assertTrue(ex.getMessage().contains(OID_3));
    }

}
