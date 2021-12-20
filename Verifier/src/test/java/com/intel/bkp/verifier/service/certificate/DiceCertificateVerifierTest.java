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

package com.intel.bkp.verifier.service.certificate;

import com.intel.bkp.verifier.exceptions.SigmaException;
import com.intel.bkp.verifier.model.TrustedRootHash;
import com.intel.bkp.verifier.x509.X509CertificateChainVerifier;
import com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier;
import com.intel.bkp.verifier.x509.X509CertificateSubjectKeyIdentifierVerifier;
import com.intel.bkp.verifier.x509.X509CertificateUeidVerifier;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.Set;

import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_MULTI_TCB_INFO;
import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_TCB_INFO;
import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_UEID;
import static com.intel.bkp.verifier.x509.X509CertificateBasicConstraintsVerifier.CA_TRUE_PATHLENGTH_NONE;
import static com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier.KEY_PURPOSE_ATTEST_INIT;
import static com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier.KEY_PURPOSE_ATTEST_LOC;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiceCertificateVerifierTest {

    private static final byte[] DEVICE_ID = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
    private static final byte[] DICE_ROOT_CERT = new byte[]{7, 8};
    private static final String DICE_ROOT_HASH = DigestUtils.sha256Hex(DICE_ROOT_CERT);
    private static final Set<String> DICE_EXTENSION_OIDS = Set.of(TCG_DICE_TCB_INFO.getOid(),
        TCG_DICE_MULTI_TCB_INFO.getOid(), TCG_DICE_UEID.getOid());

    @Mock
    private X509Certificate certificate;

    @Mock
    private X509CertificateChainVerifier certificateParentVerifier;

    @Mock
    private X509CertificateUeidVerifier ueidVerifier;

    @Mock
    private X509CertificateExtendedKeyUsageVerifier extendedKeyUsageVerifier;

    @Mock
    private X509CertificateSubjectKeyIdentifierVerifier subjectKeyIdentifierVerifier;

    @Mock
    private CrlVerifier crlVerifier;

    @Mock
    private RootHashVerifier rootHashVerifier;

    @Mock
    private TrustedRootHash trustedRootHash;

    @InjectMocks
    private DiceCertificateVerifier sut;

    private LinkedList<X509Certificate> certificates;

    @BeforeEach
    void setUp() {
        sut.withDeviceId(DEVICE_ID);
        certificates = new LinkedList<>();
        certificates.add(certificate);
    }

    @Test
    void verifyAliasChain_ParentVerificationFails_Throws() {
        // given
        mockCertificateParentVerification(false);

        // when-then
        Assertions.assertThrows(SigmaException.class, () -> sut.verifyAliasChain(certificates));
    }

    @Test
    void verifyAliasChain_UeidVerificationFails_Throws() {
        // given
        mockCertificateParentVerification(true);
        mockUeidVerification(false);

        // when-then
        Assertions.assertThrows(SigmaException.class, () -> sut.verifyAliasChain(certificates));
    }

    @Test
    void verifyAliasChain_SkiVerificationFails_Throws() {
        // given
        mockCertificateParentVerification(true);
        mockUeidVerification(true);
        mockSkiVerification(false);

        // when-then
        Assertions.assertThrows(SigmaException.class, () -> sut.verifyAliasChain(certificates));
    }

    @Test
    void verifyAliasChain_RootHashVerificationFails_Throws() {
        // given
        mockCertificateParentVerification(true);
        mockUeidVerification(true);
        mockSkiVerification(true);
        mockRootHashVerification(false);

        // when-then
        Assertions.assertThrows(SigmaException.class, () -> sut.verifyAliasChain(certificates));
    }

    @Test
    void verifyAliasChain_CrlVerificationFails_Throws() {
        // given
        mockCertificateParentVerification(true);
        mockUeidVerification(true);
        mockSkiVerification(true);
        mockRootHashVerification(true);
        mockCrlVerification(false);

        // when-then
        Assertions.assertThrows(SigmaException.class, () -> sut.verifyAliasChain(certificates));
    }

    @Test
    void verifyAliasChain_ExtendedKeyUsageVerificationFails_Throws() {
        // given
        mockCertificateParentVerification(true);
        mockUeidVerification(true);
        mockSkiVerification(true);
        mockRootHashVerification(true);
        mockCrlVerification(true);
        mockExtendedKeyUsageVerification(false);

        // when-then
        Assertions.assertThrows(SigmaException.class, () -> sut.verifyAliasChain(certificates));
    }

    @Test
    void verifyAliasChain_AllPassed() {
        // given
        mockCertificateParentVerification(true);
        mockUeidVerification(true);
        mockSkiVerification(true);
        mockExtendedKeyUsageVerification(true);
        mockRootHashVerification(true);
        mockCrlVerification(true);

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.verifyAliasChain(certificates));
        verify(certificateParentVerifier).rootBasicConstraints(CA_TRUE_PATHLENGTH_NONE);
        verify(certificateParentVerifier).knownExtensionOids(DICE_EXTENSION_OIDS);
        verify(extendedKeyUsageVerifier).verify(KEY_PURPOSE_ATTEST_INIT, KEY_PURPOSE_ATTEST_LOC);
        verify(ueidVerifier).verify(DEVICE_ID);
    }

    private void mockCertificateParentVerification(boolean verificationPassed) {
        when(certificateParentVerifier.certificates(certificates)).thenReturn(certificateParentVerifier);
        when(certificateParentVerifier.rootBasicConstraints(anyInt())).thenReturn(certificateParentVerifier);
        when(certificateParentVerifier.knownExtensionOids(any())).thenReturn(certificateParentVerifier);
        when(certificateParentVerifier.verify()).thenReturn(verificationPassed);
    }

    private void mockUeidVerification(boolean verificationPassed) {
        when(ueidVerifier.certificates(certificates)).thenReturn(ueidVerifier);
        when(ueidVerifier.verify(any())).thenReturn(verificationPassed);
    }

    private void mockSkiVerification(boolean verificationPassed) {
        when(subjectKeyIdentifierVerifier.certificates(certificates)).thenReturn(subjectKeyIdentifierVerifier);
        when(subjectKeyIdentifierVerifier.verify()).thenReturn(verificationPassed);
    }

    private void mockExtendedKeyUsageVerification(boolean verificationPassed) {
        when(extendedKeyUsageVerifier.certificate(certificates.getFirst())).thenReturn(extendedKeyUsageVerifier);
        when(extendedKeyUsageVerifier.verify(any())).thenReturn(verificationPassed);
    }

    private void mockRootHashVerification(boolean verificationPassed) {
        when(trustedRootHash.getDice()).thenReturn(DICE_ROOT_HASH);
        when(rootHashVerifier.verifyRootHash(certificate, DICE_ROOT_HASH)).thenReturn(verificationPassed);
    }

    private void mockCrlVerification(boolean verificationPassed) {
        when(crlVerifier.certificates(certificates)).thenReturn(crlVerifier);
        when(crlVerifier.doNotRequireCrlForLeafCertificate()).thenReturn(crlVerifier);
        when(crlVerifier.verify()).thenReturn(verificationPassed);
    }
}
