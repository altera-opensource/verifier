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
import com.intel.bkp.ext.core.manufacturing.model.PufType;
import com.intel.bkp.ext.utils.HexConverter;
import com.intel.bkp.verifier.dp.DistributionPointConnector;
import com.intel.bkp.verifier.dp.ProxyCallbackFactory;
import com.intel.bkp.verifier.exceptions.SigmaException;
import com.intel.bkp.verifier.interfaces.IProxyCallback;
import com.intel.bkp.verifier.model.IpcsDistributionPoint;
import com.intel.bkp.verifier.model.TrustedRootHash;
import com.intel.bkp.verifier.x509.X509CertificateChainVerifier;
import com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier.KEY_PURPOSE_CODE_SIGNING;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class S10CertificateVerifierTest {

    private static final byte[] DEVICE_ID = HexConverter.fromHex("0011223344556677");
    private static final byte[] WRONG_DEVICE_ID = HexConverter.fromHex("7766554433221100");

    private static final byte[] S10_ROOT_CERT = new byte[] { 5, 6 };
    private static final String S10_ROOT_HASH = DigestUtils.sha256Hex(S10_ROOT_CERT);

    private static final TrustedRootHash TRUSTED_ROOT_HASH = new TrustedRootHash(S10_ROOT_HASH, null);
    private static final IpcsDistributionPoint DISTRIBUTION_POINT = new IpcsDistributionPoint(null,
        TRUSTED_ROOT_HASH, null, null);

    private static final byte[] ATTESTATION_CERT = new byte[] { 1, 2 };
    private static final byte[] PARENT_CERT = new byte[] { 3, 4 };

    @Mock
    private X509Certificate x509AttestationCert;

    @Mock
    private X509Certificate x509ParentCert;

    @Mock
    private X509Certificate x509RootCert;

    @Mock
    private DistributionPointConnector connector;

    @Mock
    private X509CertificateParser certificateParser;

    @Mock
    private X509CertificateChainVerifier certificateChainVerifier;

    @Mock
    private X509CertificateExtendedKeyUsageVerifier certificateUsageVerifier;

    @Mock
    private CrlVerifier crlVerifier;

    @Mock
    private ProxyCallbackFactory proxyCallbackFactory;

    @Mock
    private IProxyCallback proxyCallbackMock;

    @Mock
    private DistributionPointAddressProvider addressProvider;

    @Mock
    private RootHashVerifier rootHashVerifier;

    @InjectMocks
    private S10CertificateVerifier sut;

    @BeforeEach
    void setUp() {
        setUpCertificates();
        sut.withDistributionPoint(DISTRIBUTION_POINT);
    }

    @Test
    void verify() {
        // given
        mockCertificateParentVerification(true);
        mockCertificateUsageVerification(true);
        mockRootHashVerification(true);
        mockCrlVerification(true);

        // when
        Assertions.assertDoesNotThrow(() -> sut.verify(DEVICE_ID, PufType.getPufTypeHex(PufType.EFUSE)));
    }

    @Test
    void verify_SerialNumNotMatchDeviceId_Throws() {
        // when-then
        SigmaException se = Assertions.assertThrows(SigmaException.class,
            () -> sut.verify(WRONG_DEVICE_ID, PufType.getPufTypeHex(PufType.EFUSE)));

        Assertions.assertEquals(se.getMessage(), "Certificate Serial Number does not match device id.");
    }

    @Test
    void verify_ParentVerificationFails_Throws() {
        // given
        mockCertificateParentVerification(false);

        // when-then
        Assertions.assertThrows(SigmaException.class,
            () -> sut.verify(DEVICE_ID, PufType.getPufTypeHex(PufType.EFUSE)));
    }

    @Test
    void verify_UsageVerificationFails_Throws() {
        // given
        mockCertificateParentVerification(true);
        mockCertificateUsageVerification(false);

        // when-then
        Assertions.assertThrows(SigmaException.class,
            () -> sut.verify(DEVICE_ID, PufType.getPufTypeHex(PufType.EFUSE)));
    }

    @Test
    void verify_CrlVerificationFails_Throws() throws CertificateEncodingException {
        // given
        mockCertificateParentVerification(true);
        mockCertificateUsageVerification(true);
        mockRootHashVerification(true);
        mockCrlVerification(false);

        // when-then
        SigmaException thrown = Assertions.assertThrows(SigmaException.class,
            () -> sut.verify(DEVICE_ID, PufType.getPufTypeHex(PufType.EFUSE)));
        Assertions.assertTrue(thrown.getMessage().contains("Device with device id 0011223344556677 is revoked."));
    }

    @Test
    void verify_BlankRootHash_RootHashVerificationPassed() {
        // given
        mockCertificateParentVerification(true);
        mockCertificateUsageVerification(true);
        mockCrlVerification(true);
        mockRootHashVerification(true);

        // when-then
        Assertions.assertDoesNotThrow(
            () -> sut.verify(DEVICE_ID, PufType.getPufTypeHex(PufType.EFUSE)));
    }

    @Test
    void verify_RootHashVerificationFails_Throws() {
        // given
        mockCertificateParentVerification(true);
        mockCertificateUsageVerification(true);
        mockRootHashVerification(false);

        // when-then
        Assertions.assertThrows(SigmaException.class,
            () -> sut.verify(DEVICE_ID,
                PufType.getPufTypeHex(PufType.EFUSE)));
    }

    private void setUpCertificates() {
        when(connector.getBytes(any())).thenReturn(ATTESTATION_CERT, PARENT_CERT);
        when(connector.getString(any())).thenReturn(new String(S10_ROOT_CERT));

        when(certificateParser.toX509(any(byte[].class))).thenReturn(x509AttestationCert, x509ParentCert);
        when(certificateParser.toX509(anyString())).thenReturn(x509RootCert);
        when(certificateParser.getPathToIssuerCertificateLocation(any())).thenReturn("test");
        when(x509AttestationCert.getSerialNumber()).thenReturn(CrlSerialNumberBuilder.convertToBigInteger(DEVICE_ID));
    }

    private void mockCertificateParentVerification(boolean verificationPassed) {
        when(certificateChainVerifier.certificates(any())).thenReturn(certificateChainVerifier);
        when(certificateChainVerifier.verify()).thenReturn(verificationPassed);
    }

    private void mockCertificateUsageVerification(boolean verificationPassed) {
        when(certificateUsageVerifier.certificate(any())).thenReturn(certificateUsageVerifier);
        when(certificateUsageVerifier.verify(KEY_PURPOSE_CODE_SIGNING)).thenReturn(verificationPassed);
    }

    private void mockRootHashVerification(boolean verificationPassed) {
        when(rootHashVerifier.verifyRootHash(any(), eq(S10_ROOT_HASH))).thenReturn(verificationPassed);
    }

    private void mockCrlVerification(boolean verificationPassed) {
        when(crlVerifier.certificates(any())).thenReturn(crlVerifier);
        when(crlVerifier.verify()).thenReturn(verificationPassed);
    }
}
