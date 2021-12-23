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

import com.intel.bkp.ext.core.crl.CrlSerialNumberBuilder;
import com.intel.bkp.verifier.exceptions.SigmaException;
import com.intel.bkp.verifier.model.TrustedRootHash;
import com.intel.bkp.verifier.x509.X509CertificateChainVerifier;
import com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier;
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

import static com.intel.bkp.ext.utils.HexConverter.fromHex;
import static com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier.KEY_PURPOSE_CODE_SIGNING;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class S10ChainVerifierTest {

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
    private X509CertificateChainVerifier certificateChainVerifier;

    @Mock
    private X509CertificateExtendedKeyUsageVerifier extendedKeyUsageVerifier;

    @Mock
    private CrlVerifier crlVerifier;

    @Mock
    private RootHashVerifier rootHashVerifier;

    @Mock
    private TrustedRootHash trustedRootHash;

    @InjectMocks
    private S10ChainVerifier sut;

    private final LinkedList<X509Certificate> certificates = new LinkedList<>();

    @BeforeEach
    void setUp() {
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
        Assertions.assertDoesNotThrow(() -> sut.verifyChain(certificates));
    }

    @Test
    void verifyChain_SerialNumNotMatchDeviceId_Throws() {
        // given
        mockSerialNumberOfAttestationCert();
        sut.setDeviceId(WRONG_DEVICE_ID);

        // when-then
        assertVerifyChainThrowsSigmaException("Certificate Serial Number does not match device id.");
    }

    @Test
    void verifyChain_ParentVerificationFails_Throws() {
        // given
        mockSerialNumberOfAttestationCert();
        mockCertificateParentVerification(false);

        // when-then
        assertVerifyChainThrowsSigmaException("Parent signature verification in X509 attestation chain failed.");
    }

    @Test
    void verifyChain_UsageVerificationFails_Throws() {
        // given
        mockSerialNumberOfAttestationCert();
        mockCertificateParentVerification(true);
        mockCertificateUsageVerification(false);

        // when-then
        assertVerifyChainThrowsSigmaException("Attestation certificate is invalid.");
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
        assertVerifyChainThrowsSigmaException("Device with device id 0011223344556677 is revoked.");
    }

    @Test
    void verifyChain_RootHashVerificationFails_Throws() {
        // given
        mockSerialNumberOfAttestationCert();
        mockCertificateParentVerification(true);
        mockCertificateUsageVerification(true);
        mockRootHashVerification(false);

        // when-then
        assertVerifyChainThrowsSigmaException("Root hash in X509 attestation chain is different from trusted root "
            + "hash.");
    }

    private void assertVerifyChainThrowsSigmaException(String expectedExceptionMessage) {
        SigmaException thrown = Assertions.assertThrows(SigmaException.class, () -> sut.verifyChain(certificates));
        Assertions.assertEquals(thrown.getMessage(), expectedExceptionMessage);
    }

    private void setUpCertificates() {
        certificates.add(x509AttestationCert);
        certificates.add(x509ParentCert);
        certificates.add(x509RootCert);
    }

    private void mockSerialNumberOfAttestationCert() {
        when(x509AttestationCert.getSerialNumber()).thenReturn(CrlSerialNumberBuilder.convertToBigInteger(DEVICE_ID));
    }

    private void mockCertificateParentVerification(boolean verificationPassed) {
        when(certificateChainVerifier.certificates(certificates)).thenReturn(certificateChainVerifier);
        when(certificateChainVerifier.verify()).thenReturn(verificationPassed);
    }

    private void mockCertificateUsageVerification(boolean verificationPassed) {
        when(extendedKeyUsageVerifier.certificate(x509AttestationCert)).thenReturn(extendedKeyUsageVerifier);
        when(extendedKeyUsageVerifier.verify(KEY_PURPOSE_CODE_SIGNING)).thenReturn(verificationPassed);
    }

    private void mockRootHashVerification(boolean verificationPassed) {
        when(trustedRootHash.getS10()).thenReturn(S10_ROOT_HASH);
        when(rootHashVerifier.verifyRootHash(x509RootCert, S10_ROOT_HASH)).thenReturn(verificationPassed);
    }

    private void mockCrlVerification(boolean verificationPassed) {
        when(crlVerifier.certificates(certificates)).thenReturn(crlVerifier);
        when(crlVerifier.verify()).thenReturn(verificationPassed);
    }
}
