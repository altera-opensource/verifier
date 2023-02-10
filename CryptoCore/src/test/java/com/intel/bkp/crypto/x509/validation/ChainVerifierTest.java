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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.intel.bkp.crypto.x509.validation.ChainVerifier.COMMON_EXTENSION_OIDS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ChainVerifierTest {

    // https://tsci.intel.com/content/IPCS/certs/attestation_5ADF841DDEAD944E_00000002.cer
    private static final String ATTESTATION_CERT_FILENAME = "attestation_5ADF841DDEAD944E_00000002.cer";
    // https://tsci.intel.com/content/IPCS/certs/IPCSSigningCA.cer
    private static final String PARENT_CERT_FILENAME = "IPCSSigningCA.cer";
    // https://tsci.intel.com/content/IPCS/certs/IPCS.cer
    private static final String ROOT_CERT_FILENAME = "IPCS.cer";

    private static X509Certificate attestationCert;
    private static X509Certificate parentCert;
    private static X509Certificate rootCert;

    private LinkedList<X509Certificate> list;

    @Mock
    private SignatureVerifier signatureVerifier;

    @Mock
    private ValidityVerifier validityVerifier;

    @Mock
    private IssuerVerifier issuerVerifier;

    @Mock
    private AuthorityKeyIdentifierVerifier authorityKeyIdentifierVerifier;

    @Mock
    private BasicConstraintsVerifier basicConstraintsVerifier;

    @Mock
    private KeyUsageVerifier keyUsageVerifier;

    @Mock
    private CriticalExtensionsVerifier criticalExtensionsVerifier;

    @InjectMocks
    private ChainVerifier sut;

    @BeforeAll
    static void init() throws Exception {
        attestationCert = TestUtil.loadCertificate(ATTESTATION_CERT_FILENAME);
        parentCert = TestUtil.loadCertificate(PARENT_CERT_FILENAME);
        rootCert = TestUtil.loadCertificate(ROOT_CERT_FILENAME);
    }

    @BeforeEach
    void setUp() {
        list = new LinkedList<>();
        sut.certificates(list);
    }

    @Test
    void verify_VerifyAllChecksArePerformed() {
        // given
        addToList(attestationCert, parentCert, rootCert);
        mockAllChecks();

        // when
        final boolean result = sut.verify();

        // then
        Assertions.assertTrue(result);
        verify(signatureVerifier).verify(attestationCert, parentCert);
        verify(signatureVerifier).verify(parentCert, rootCert);
        verify(signatureVerifier).verify(rootCert, rootCert);
        verify(validityVerifier).verify(attestationCert);
        verify(validityVerifier).verify(parentCert);
        verify(validityVerifier).verify(rootCert);
        verify(issuerVerifier).verify(attestationCert, parentCert);
        verify(issuerVerifier).verify(parentCert, rootCert);
        verify(issuerVerifier).verify(rootCert, rootCert);
        verify(authorityKeyIdentifierVerifier).verify(attestationCert, parentCert);
        verify(authorityKeyIdentifierVerifier).verify(parentCert, rootCert);
        verify(authorityKeyIdentifierVerifier).verify(rootCert, rootCert);
        verify(keyUsageVerifier).verify(attestationCert, KeyUsage.DIGITAL_SIGNATURE);
        verify(keyUsageVerifier).verify(parentCert, KeyUsage.KEY_CERT_SIGN);
        verify(keyUsageVerifier).verify(rootCert, KeyUsage.KEY_CERT_SIGN);
        verify(basicConstraintsVerifier).verify(parentCert, 0);
        verify(basicConstraintsVerifier).verify(rootCert, 1);
        verifyNoMoreInteractions(basicConstraintsVerifier);
        verify(criticalExtensionsVerifier).verify(attestationCert, COMMON_EXTENSION_OIDS);
        verify(criticalExtensionsVerifier).verify(parentCert, COMMON_EXTENSION_OIDS);
        verify(criticalExtensionsVerifier).verify(rootCert, COMMON_EXTENSION_OIDS);
    }

    @Test
    void verify_knownExtensionOids() {
        // given
        final var additionalOids = Set.of("2.23.133.5.4.5", "1.2.3.4");
        final var allOids = Stream.concat(COMMON_EXTENSION_OIDS.stream(), additionalOids.stream())
                .collect(Collectors.toSet());
        addToList(attestationCert, parentCert, rootCert);
        mockAllChecks();

        // when
        sut.knownExtensionOids(additionalOids).verify();

        // then
        verify(criticalExtensionsVerifier).verify(attestationCert, allOids);
        verify(criticalExtensionsVerifier).verify(parentCert, allOids);
        verify(criticalExtensionsVerifier).verify(rootCert, allOids);
    }

    @Test
    void verify_With3CorrectCertificates_ReturnsTrue() {
        // given
        addToList(attestationCert, parentCert, rootCert);
        mockAllChecks();

        // when
        boolean result = sut.verify();

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verify_With2CorrectCertificates_ReturnsTrue() {
        // given
        addToList(attestationCert, parentCert);
        mockAllChecks();

        // when
        boolean result = sut.verify();

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verify_With1Certificate_ReturnsFalse() {
        // given
        list.add(attestationCert);

        // when
        boolean result = sut.verify();

        // then
        Assertions.assertFalse(result);
    }

    private void addToList(X509Certificate... cert) {
        list.addAll(List.of(cert));
    }

    private void mockAllChecks() {
        when(validityVerifier.verify(any())).thenReturn(true);
        when(signatureVerifier.verify(any(X509Certificate.class), any())).thenReturn(true);
        when(issuerVerifier.verify(any(), any())).thenReturn(true);
        when(authorityKeyIdentifierVerifier.verify(any(), any())).thenReturn(true);
        when(keyUsageVerifier.verify(any(), any())).thenReturn(true);
        when(criticalExtensionsVerifier.verify(any(), any())).thenReturn(true);
        when(basicConstraintsVerifier.verify(any(), anyInt())).thenReturn(true);
    }
}
