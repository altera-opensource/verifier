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

import com.intel.bkp.crypto.x509.validation.ChainVerifier;
import com.intel.bkp.crypto.x509.validation.ExtendedKeyUsageVerifier;
import com.intel.bkp.crypto.x509.validation.SubjectKeyIdentifierVerifier;
import com.intel.bkp.fpgacerts.dice.subject.DiceSubjectVerifier;
import com.intel.bkp.fpgacerts.dice.tcbinfo.verification.TcbInfoVerifier;
import com.intel.bkp.fpgacerts.dice.ueid.UeidVerifier;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.Set;

import static com.intel.bkp.crypto.x509.validation.ExtendedKeyUsageVerifier.KEY_PURPOSE_CODE_SIGNING;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_MULTI_TCB_INFO;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_TCB_INFO;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_UEID;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiceChainVerifierBaseTest {

    private static class DiceChainVerifierTestImpl extends DiceChainVerifierBase {

        DiceChainVerifierTestImpl(ExtendedKeyUsageVerifier extendedKeyUsageVerifier,
                                  ChainVerifier chainVerifier, DiceCrlVerifier crlVerifier,
                                  RootHashVerifier rootHashVerifier, UeidVerifier ueidVerifier,
                                  SubjectKeyIdentifierVerifier subjectKeyIdentifierVerifier,
                                  String trustedRootHash, TcbInfoVerifier tcbInfoVerifier,
                                  DiceSubjectVerifier diceSubjectVerifier) {
            super(extendedKeyUsageVerifier, chainVerifier, crlVerifier, rootHashVerifier, ueidVerifier,
                subjectKeyIdentifierVerifier, trustedRootHash, tcbInfoVerifier, diceSubjectVerifier);
        }

        @Override
        protected String[] getExpectedLeafCertKeyPurposes() {
            return new String[]{KEY_PURPOSE};
        }

        @Override
        protected void handleVerificationFailure(String failureDetails) {
            throw new RuntimeException(failureDetails);
        }
    }

    private static final byte[] DEVICE_ID = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
    private static final String KEY_PURPOSE = KEY_PURPOSE_CODE_SIGNING;
    private static final byte[] DICE_ROOT_CERT = new byte[]{7, 8};
    private static final String DICE_ROOT_HASH = DigestUtils.sha256Hex(DICE_ROOT_CERT);
    private static final Set<String> DICE_EXTENSION_OIDS = Set.of(TCG_DICE_TCB_INFO.getOid(),
        TCG_DICE_MULTI_TCB_INFO.getOid(), TCG_DICE_UEID.getOid());

    @Mock
    private X509Certificate certificate;

    @Mock
    private ChainVerifier chainVerifier;

    @Mock
    private UeidVerifier ueidVerifier;

    @Mock
    private ExtendedKeyUsageVerifier extendedKeyUsageVerifier;

    @Mock
    private SubjectKeyIdentifierVerifier subjectKeyIdentifierVerifier;

    @Mock
    private DiceCrlVerifier crlVerifier;

    @Mock
    private RootHashVerifier rootHashVerifier;

    @Mock
    private TcbInfoVerifier tcbInfoVerifier;

    @Mock
    private DiceSubjectVerifier diceSubjectVerifier;

    private DiceChainVerifierTestImpl sut;

    private LinkedList<X509Certificate> certificates;

    @BeforeEach
    void setUp() {
        sut = new DiceChainVerifierTestImpl(extendedKeyUsageVerifier, chainVerifier, crlVerifier, rootHashVerifier,
            ueidVerifier, subjectKeyIdentifierVerifier, DICE_ROOT_HASH, tcbInfoVerifier, diceSubjectVerifier);
        sut.setDeviceId(DEVICE_ID);
        certificates = new LinkedList<>();
        certificates.add(certificate);
    }

    @Test
    void verifyChain_ParentVerificationFails_Throws() {
        // given
        final String expectedError = "Parent signature verification in X509 attestation chain failed.";
        mockCertificateParentVerification(false);

        // when-then
        final var ex = Assertions.assertThrows(RuntimeException.class, () -> sut.verifyChain(certificates));
        Assertions.assertEquals(expectedError, ex.getMessage());
    }

    @Test
    void verifyChain_UeidVerificationFails_Throws() {
        // given
        final String expectedError = "One of certificates in X509 attestation chain has invalid UEID extension value.";
        mockCertificateParentVerification(true);
        mockUeidVerification(false);

        // when-then
        final var ex = Assertions.assertThrows(RuntimeException.class, () -> sut.verifyChain(certificates));
        Assertions.assertEquals(expectedError, ex.getMessage());
    }

    @Test
    void verifyChain_SkiVerificationFails_Throws() {
        // given
        final String expectedError = "One of certificates in X509 attestation chain has invalid SKI extension value.";
        mockCertificateParentVerification(true);
        mockUeidVerification(true);
        mockSkiVerification(false);

        // when-then
        final var ex = Assertions.assertThrows(RuntimeException.class, () -> sut.verifyChain(certificates));
        Assertions.assertEquals(expectedError, ex.getMessage());
    }

    @Test
    void verifyChain_RootHashVerificationFails_Throws() {
        // given
        final String expectedError = "Root hash in X509 DICE chain is different from trusted root hash.";
        mockCertificateParentVerification(true);
        mockUeidVerification(true);
        mockSkiVerification(true);
        mockRootHashVerification(false);

        // when-then
        final var ex = Assertions.assertThrows(RuntimeException.class, () -> sut.verifyChain(certificates));
        Assertions.assertEquals(expectedError, ex.getMessage());
    }

    @Test
    void verifyChain_ExtendedKeyUsageVerificationFails_Throws() {
        // given
        final String expectedError = "Leaf certificate has invalid key usages.";
        mockCertificateParentVerification(true);
        mockUeidVerification(true);
        mockSkiVerification(true);
        mockRootHashVerification(true);
        mockExtendedKeyUsageVerification(false);

        // when-then
        final var ex = Assertions.assertThrows(RuntimeException.class, () -> sut.verifyChain(certificates));
        Assertions.assertEquals(expectedError, ex.getMessage());
    }

    @Test
    void verifyChain_DiceSubjectVerificationFails_Throws() {
        // given
        final String expectedError = "DICE subject validation failed.";
        mockCertificateParentVerification(true);
        mockUeidVerification(true);
        mockSkiVerification(true);
        mockRootHashVerification(true);
        mockExtendedKeyUsageVerification(true);
        mockDiceSubjectVerification(false);

        // when-then
        final var ex = Assertions.assertThrows(RuntimeException.class, () -> sut.verifyChain(certificates));
        Assertions.assertEquals(expectedError, ex.getMessage());
    }

    @Test
    void verifyChain_CrlVerificationFails_Throws() {
        // given
        final String expectedError = "One of the certificates in chain is revoked.";
        mockCertificateParentVerification(true);
        mockUeidVerification(true);
        mockSkiVerification(true);
        mockRootHashVerification(true);
        mockExtendedKeyUsageVerification(true);
        mockDiceSubjectVerification(true);
        mockCrlVerification(false);

        // when-then
        final var ex = Assertions.assertThrows(RuntimeException.class, () -> sut.verifyChain(certificates));
        Assertions.assertEquals(expectedError, ex.getMessage());
    }

    @Test
    void verifyChain_AllPassed() {
        // given
        mockCertificateParentVerification(true);
        mockUeidVerification(true);
        mockSkiVerification(true);
        mockRootHashVerification(true);
        mockExtendedKeyUsageVerification(true);
        mockDiceSubjectVerification(true);
        mockCrlVerification(true);
        mockTcbInfoVerification(true);

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.verifyChain(certificates));

        // then
        verify(chainVerifier).knownExtensionOids(DICE_EXTENSION_OIDS);
        verify(extendedKeyUsageVerifier).verify(KEY_PURPOSE);
        verify(ueidVerifier).verify(DEVICE_ID);
        verify(tcbInfoVerifier).verify();
    }

    @Test
    void verifyChain_TcbInfoValidationFails_Throws() {
        // given
        final String expectedError = "TcbInfo validation failed.";
        mockCertificateParentVerification(true);
        mockUeidVerification(true);
        mockSkiVerification(true);
        mockExtendedKeyUsageVerification(true);
        mockRootHashVerification(true);
        mockCrlVerification(true);
        mockDiceSubjectVerification(true);
        mockTcbInfoVerification(false);

        // when-then
        final var ex = Assertions.assertThrows(RuntimeException.class,
            () -> sut.verifyChain(certificates));
        Assertions.assertEquals(expectedError, ex.getMessage());
    }

    private void mockCertificateParentVerification(boolean verificationPassed) {
        when(chainVerifier.certificates(certificates)).thenReturn(chainVerifier);
        when(chainVerifier.knownExtensionOids(any())).thenReturn(chainVerifier);
        when(chainVerifier.verify()).thenReturn(verificationPassed);
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
        when(rootHashVerifier.verifyRootHash(certificate, DICE_ROOT_HASH)).thenReturn(verificationPassed);
    }

    private void mockCrlVerification(boolean verificationPassed) {
        when(crlVerifier.certificates(certificates)).thenReturn(crlVerifier);
        when(crlVerifier.doNotRequireCrlForLeafCertificate()).thenReturn(crlVerifier);
        when(crlVerifier.verify()).thenReturn(verificationPassed);
    }

    private void mockDiceSubjectVerification(boolean verificationPassed) {
        when(diceSubjectVerifier.certificates(certificates)).thenReturn(diceSubjectVerifier);
        when(diceSubjectVerifier.verify()).thenReturn(verificationPassed);
    }

    private void mockTcbInfoVerification(boolean verificationPassed) {
        when(tcbInfoVerifier.certificates(certificates)).thenReturn(tcbInfoVerifier);
        when(tcbInfoVerifier.verify()).thenReturn(verificationPassed);
    }
}
