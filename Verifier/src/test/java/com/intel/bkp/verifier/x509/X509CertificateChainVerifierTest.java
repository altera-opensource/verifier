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
import com.intel.bkp.verifier.model.AttestationOid;
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

import static com.intel.bkp.verifier.x509.X509CertificateChainVerifier.COMMON_EXTENSION_OIDS;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@ExtendWith(MockitoExtension.class)
class X509CertificateChainVerifierTest {

    private static final String TEST_FOLDER = "certs/";

    // https://tsci.intel.com/content/IPCS/certs/attestation_5ADF841DDEAD944E_00000002.cer
    private static final String ATTESTATION_CERT_FILENAME = "attestation_5ADF841DDEAD944E_00000002.cer";
    // https://tsci.intel.com/content/IPCS/certs/IPCSSigningCA.cer
    private static final String PARENT_CERT_FILENAME = "IPCSSigningCA.cer";
    // https://tsci.intel.com/content/IPCS/certs/IPCS.cer
    private static final String ROOT_CERT_FILENAME = "IPCS.cer";

    private static final X509CertificateParser X509_PARSER = new X509CertificateParser();

    private static X509Certificate attestationCert;
    private static X509Certificate parentCert;
    private static X509Certificate rootCert;

    private LinkedList<X509Certificate> list;

    @Mock
    private X509CertificateParentVerifier certificateParentVerifier;

    @Mock
    private X509CertificateValidityVerifier certificateValidityVerifier;

    @Mock
    private X509CertificateIssuerVerifier certificateIssuerVerifier;

    @Mock
    private X509CertificateAuthorityKeyIdentifierVerifier certificateAuthorityKeyIdentifierVerifier;

    @Mock
    private X509CertificateBasicConstraintsVerifier certificateBasicConstraintsVerifier;

    @Mock
    private X509CertificateKeyUsageVerifier certificateKeyUsageVerifier;

    @Mock
    private X509CertificateCriticalExtensionsVerifier criticalExtensionsVerifier;

    @InjectMocks
    private X509CertificateChainVerifier sut;

    @BeforeAll
    static void init() throws Exception {
        attestationCert = X509_PARSER.toX509(Utils.readFromResources(TEST_FOLDER, ATTESTATION_CERT_FILENAME));
        parentCert = X509_PARSER.toX509(Utils.readFromResources(TEST_FOLDER, PARENT_CERT_FILENAME));
        rootCert = X509_PARSER.toX509(Utils.readFromResources(TEST_FOLDER, ROOT_CERT_FILENAME));
    }

    @BeforeEach
    void setUp() {
        list = new LinkedList<>();
        sut.certificates(list);
    }

    @Test
    void verify_VerifyAllChecksArePerformed() throws Exception {
        // given
        addToList(attestationCert, parentCert, rootCert);

        // when
        sut.verify();

        // then
        verify(certificateParentVerifier).verify(attestationCert, parentCert);
        verify(certificateParentVerifier).verify(parentCert, rootCert);
        verify(certificateParentVerifier).verify(rootCert, rootCert);
        verify(certificateValidityVerifier).verify(attestationCert);
        verify(certificateValidityVerifier).verify(parentCert);
        verify(certificateValidityVerifier).verify(rootCert);
        verify(certificateIssuerVerifier).verify(attestationCert, parentCert);
        verify(certificateIssuerVerifier).verify(parentCert, rootCert);
        verify(certificateIssuerVerifier).verify(rootCert, rootCert);
        verify(certificateAuthorityKeyIdentifierVerifier).verify(attestationCert, parentCert);
        verify(certificateAuthorityKeyIdentifierVerifier).verify(parentCert, rootCert);
        verify(certificateAuthorityKeyIdentifierVerifier).verify(rootCert, rootCert);
        verify(certificateKeyUsageVerifier).verify(attestationCert, KeyUsage.DIGITAL_SIGNATURE);
        verify(certificateKeyUsageVerifier).verify(parentCert, KeyUsage.KEY_CERT_SIGN);
        verify(certificateKeyUsageVerifier).verify(rootCert, KeyUsage.KEY_CERT_SIGN);
        verify(certificateBasicConstraintsVerifier).verify(parentCert, 0);
        verify(certificateBasicConstraintsVerifier).verify(rootCert, 1);
        verifyNoMoreInteractions(certificateBasicConstraintsVerifier);
        verify(criticalExtensionsVerifier).verify(attestationCert, COMMON_EXTENSION_OIDS);
        verify(criticalExtensionsVerifier).verify(parentCert, COMMON_EXTENSION_OIDS);
        verify(criticalExtensionsVerifier).verify(rootCert, COMMON_EXTENSION_OIDS);
    }

    @Test
    void verify_rootBasicConstraints() throws Exception {
        // given
        final int rootBasicConstraints = Integer.MAX_VALUE;
        addToList(attestationCert, parentCert, rootCert);

        // when
        sut.rootBasicConstraints(rootBasicConstraints).verify();

        // then
        verify(certificateBasicConstraintsVerifier).verify(parentCert, 0);
        verify(certificateBasicConstraintsVerifier).verify(rootCert, rootBasicConstraints);
        verifyNoMoreInteractions(certificateBasicConstraintsVerifier);
    }

    @Test
    void verify_knownExtensionOids() throws Exception {
        // given
        final var additionalOids = Set.of(AttestationOid.TCG_DICE_MULTI_TCB_INFO.getOid(), "1.2.3.4");
        final var allOids = Stream.concat(COMMON_EXTENSION_OIDS.stream(), additionalOids.stream())
            .collect(Collectors.toSet());
        addToList(attestationCert, parentCert, rootCert);

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

        // when
        boolean result = sut.verify();

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verify_With2CorrectCertificates_ReturnsTrue() {
        // given
        addToList(attestationCert, parentCert);

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
}
