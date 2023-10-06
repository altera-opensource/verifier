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
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import static com.intel.bkp.crypto.x509.validation.ExtendedKeyUsageVerifier.KEY_PURPOSE_CODE_SIGNING;
import static com.intel.bkp.fpgacerts.utils.DeviceIdUtils.getS10CertificateSerialNumber;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class S10ChainVerifierBaseTest {

    private static class S10ChainVerifierTestImpl extends S10ChainVerifierBase {

        S10ChainVerifierTestImpl(ChainVerifier chainVerifier, ExtendedKeyUsageVerifier extendedKeyUsageVerifier,
                                 CrlVerifier crlVerifier, RootHashVerifier rootHashVerifier,
                                 String[] trustedRootHash) {
            super(chainVerifier, extendedKeyUsageVerifier, crlVerifier, rootHashVerifier, trustedRootHash);
        }

        @Override
        protected void handleVerificationFailure(String failureDetails) {
            throw new RuntimeException(failureDetails);
        }
    }

    private static final byte[] DEVICE_ID = fromHex("0011223344556677");
    private static final byte[] WRONG_DEVICE_ID = fromHex("7766554433221100");

    private static final byte[] S10_ROOT_CERT = new byte[]{5, 6};
    private static final String S10_ROOT_HASH = DigestUtils.sha256Hex(S10_ROOT_CERT);

    @Mock
    private X509Certificate x509AttestationCert;

    @Mock
    private X509Certificate x509ParentCert;

    @Mock
    private X509Certificate x509RootCert;

    @Mock
    private ChainVerifier chainVerifier;

    @Mock
    private ExtendedKeyUsageVerifier extendedKeyUsageVerifier;

    @Mock
    private CrlVerifier crlVerifier;

    @Mock
    private RootHashVerifier rootHashVerifier;

    @InjectMocks
    private S10ChainVerifierTestImpl sut;

    private final List<X509Certificate> certificates = new LinkedList<>();

    @BeforeEach
    void setUp() {
        sut = new S10ChainVerifierTestImpl(chainVerifier, extendedKeyUsageVerifier, crlVerifier, rootHashVerifier,
                new String[]{S10_ROOT_HASH});
        setUpCertificates();
        sut.setDeviceId(DEVICE_ID);
    }

    @Test
    void verifyChain_Success() {
        // given
        mockSerialNumberOfAttestationCert();
        mockCertificateParentVerification(true);
        mockCertificateUsageVerification(true);
        mockRootHashVerification(true);
        mockCrlVerification(true);

        // when
        assertDoesNotThrow(() -> sut.verifyChain(certificates));
    }

    @Test
    void verifyChain_SerialNumNotMatchDeviceId_Throws() {
        // given
        mockSerialNumberOfAttestationCert();
        sut.setDeviceId(WRONG_DEVICE_ID);

        // when-then
        assertVerifyChainThrowsException("Certificate Serial Number does not match device id.");
    }

    @Test
    void verifyChain_ParentVerificationFails_Throws() {
        // given
        mockSerialNumberOfAttestationCert();
        mockCertificateParentVerification(false);

        // when-then
        assertVerifyChainThrowsException("Parent signature verification in X509 attestation chain failed.");
    }

    @Test
    void verifyChain_UsageVerificationFails_Throws() {
        // given
        mockSerialNumberOfAttestationCert();
        mockCertificateParentVerification(true);
        mockCertificateUsageVerification(false);

        // when-then
        assertVerifyChainThrowsException("Attestation certificate is invalid.");
    }

    @Test
    void verifyChain_CrlVerificationFails_Throws() {
        // given
        mockSerialNumberOfAttestationCert();
        mockCertificateParentVerification(true);
        mockCertificateUsageVerification(true);
        mockRootHashVerification(true);
        mockCrlVerification(false);

        // when-then
        assertVerifyChainThrowsException("One of the certificates in chain is revoked.");
    }

    @Test
    void verifyChain_RootHashVerificationFails_Throws() {
        // given
        mockSerialNumberOfAttestationCert();
        mockCertificateParentVerification(true);
        mockCertificateUsageVerification(true);
        mockRootHashVerification(false);

        // when-then
        assertVerifyChainThrowsException("Root hash in X509 attestation chain is different from trusted root "
                + "hash.");
    }

    private void assertVerifyChainThrowsException(String expectedExceptionMessage) {
        RuntimeException thrown = assertThrows(RuntimeException.class, () -> sut.verifyChain(certificates));
        assertEquals(expectedExceptionMessage, thrown.getMessage());
    }

    private void setUpCertificates() {
        certificates.add(x509AttestationCert);
        certificates.add(x509ParentCert);
        certificates.add(x509RootCert);
    }

    private void mockSerialNumberOfAttestationCert() {
        when(x509AttestationCert.getSerialNumber()).thenReturn(getS10CertificateSerialNumber(DEVICE_ID));
    }

    private void mockCertificateParentVerification(boolean verificationPassed) {
        when(chainVerifier.certificates(certificates)).thenReturn(chainVerifier);
        when(chainVerifier.verify()).thenReturn(verificationPassed);
    }

    private void mockCertificateUsageVerification(boolean verificationPassed) {
        when(extendedKeyUsageVerifier.certificate(x509AttestationCert)).thenReturn(extendedKeyUsageVerifier);
        when(extendedKeyUsageVerifier.verify(KEY_PURPOSE_CODE_SIGNING)).thenReturn(verificationPassed);
    }

    private void mockRootHashVerification(boolean verificationPassed) {
        when(rootHashVerifier.verifyRootHash(x509RootCert, new String[]{S10_ROOT_HASH})).thenReturn(verificationPassed);
    }

    private void mockCrlVerification(boolean verificationPassed) {
        when(crlVerifier.certificates(certificates)).thenReturn(crlVerifier);
        when(crlVerifier.verify()).thenReturn(verificationPassed);
    }
}
