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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CriticalExtensionsVerifierTest {

    private static final String OID_1 = "1.2.3.1";
    private static final String OID_2 = "1.2.3.2";
    private static final String OID_3 = "1.2.3.3";

    @Mock
    private X509Certificate certificate;

    private CriticalExtensionsVerifier sut = new CriticalExtensionsVerifier();

    @Test
    void verify_NoCriticalOids_ReturnsTrue() {
        // given
        final var knownOids = Set.of(OID_1, OID_2);
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of());

        // when-then
        assertTrue(sut.verify(certificate, knownOids));
    }

    @Test
    void verify_AllCriticalOidsAreKnown_ReturnsTrue() {
        // given
        final var knownOids = Set.of(OID_1, OID_2, OID_3);
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(OID_1, OID_2));

        // when-then
        assertTrue(sut.verify(certificate, knownOids));
    }

    @Test
    void verify_CriticalOidIsUnrecognized_ReturnsFalse() {
        // given
        final var knownOids = Set.of(OID_1, OID_2);
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(OID_3));

        // when-then
        assertFalse(sut.verify(certificate, knownOids));
    }
}
