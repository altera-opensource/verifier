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
import com.intel.bkp.verifier.dp.DistributionPointConnector;
import com.intel.bkp.verifier.dp.ProxyCallbackFactory;
import com.intel.bkp.verifier.model.IpcsDistributionPoint;
import com.intel.bkp.verifier.model.TrustedRootHash;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import com.intel.bkp.verifier.x509.X509CrlParentVerifier;
import com.intel.bkp.verifier.x509.X509CrlParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Optional;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CrlVerifierTest {

    private static final String PATH_CER = "path-cer";
    private static final String S10_TRUSTED_ROOT_HASH = "hashS10";
    private static final String DICE_TRUSTED_ROOT_HASH = "hashDice";
    private static final String PROXY_HOST = "proxyhost";
    private static final Integer PROXY_PORT = 123;
    private static final TrustedRootHash TRUSTED_ROOT_HASH =
        new TrustedRootHash(S10_TRUSTED_ROOT_HASH, DICE_TRUSTED_ROOT_HASH);
    private static final IpcsDistributionPoint DISTRIBUTION_POINT =
        new IpcsDistributionPoint(PATH_CER, TRUSTED_ROOT_HASH, PROXY_HOST, PROXY_PORT);

    private static final String DEVICE_ID_REVOKED = "B51BF9E7B6169C87";
    private static final String DEVICE_ID_NOT_REVOKED = "0011223344556677";
    private static final byte[] MOCKED_CRL = new byte[]{0x01, 0x02, 0x03};

    @Mock
    private X509CRLEntry crlEntry;

    @Mock
    private X509CRL x509CRL;

    @Mock
    private PublicKey ipcsSigningPublicKey;

    @Mock
    private X509CrlParser x509CrlParser;

    @Mock
    private X509CrlParentVerifier x509CrlParentVerifier;

    @Mock
    private DistributionPointConnector connector;

    @Mock
    private ProxyCallbackFactory proxyCallbackFactory;

    @Mock
    private X509CertificateParser certificateParser;

    @Mock
    private List<X509Certificate> certificates;

    @Mock
    private X509Certificate certificate;

    @Mock
    private ListIterator<X509Certificate> certificateChainIterator;

    @Mock
    private ListIterator<X509Certificate> issuerCertsIterator;

    @InjectMocks
    private CrlVerifier sut;

    private Set revokedCertificates = new HashSet<>();

    @BeforeEach
    void setUpClass() {
        when(certificates.listIterator()).thenReturn(certificateChainIterator);
        when(certificateChainIterator.hasNext()).thenReturn(true, false);
        when(certificateChainIterator.next()).thenReturn(certificate);

        sut.withDistributionPoint(DISTRIBUTION_POINT);
    }

    @Test
    void verify_NotRevokedDevice_Success() {
        // given
        mockCrl();
        when(certificateParser.getPathToCrlDistributionPoint(certificate)).thenReturn(Optional.of("path to CRL"));
        when(certificate.getSerialNumber())
            .thenReturn(CrlSerialNumberBuilder.convertToBigInteger(DEVICE_ID_NOT_REVOKED));

        // when-then
        Assertions.assertTrue(() -> sut.verify());

        // then
        verify(x509CrlParentVerifier).verify(x509CRL, ipcsSigningPublicKey);
    }

    @Test
    void verify_WithRevokedDevice_ReturnFalse() {
        // given
        mockCrl();
        when(certificateParser.getPathToCrlDistributionPoint(certificate)).thenReturn(Optional.of("path to CRL"));
        when(certificate.getSerialNumber()).thenReturn(CrlSerialNumberBuilder.convertToBigInteger(DEVICE_ID_REVOKED));

        // when-then
        Assertions.assertFalse(() -> sut.verify());

        // then
        verify(x509CrlParentVerifier).verify(x509CRL, ipcsSigningPublicKey);
    }

    @Test
    void verify_WithCertWithoutCrlExtension_CrlNotRequired_ReturnTrue() {
        // given
        when(certificateParser.getPathToCrlDistributionPoint(certificate)).thenReturn(Optional.empty());

        // when-then
        Assertions.assertTrue(() -> sut.doNotRequireCrlForLeafCertificate().verify());

        // then
        verifyNoInteractions(x509CrlParentVerifier);
    }

    @Test
    void verify_WithCertWithoutCrlExtension_CrlRequired_ReturnFalse() {
        // given
        when(certificateParser.getPathToCrlDistributionPoint(certificate)).thenReturn(Optional.empty());

        // when-then
        Assertions.assertFalse(() -> sut.verify());

        // then
        verifyNoInteractions(x509CrlParentVerifier);
    }

    @SuppressWarnings("unchecked")
    private void mockCrl() {
        when(connector.getBytes(any())).thenReturn(MOCKED_CRL);
        when(x509CrlParser.toX509(MOCKED_CRL)).thenReturn(x509CRL);
        when(x509CRL.getRevokedCertificates()).thenReturn(revokedCertificates);
        when(crlEntry.getSerialNumber())
            .thenReturn(CrlSerialNumberBuilder.convertToBigInteger(DEVICE_ID_REVOKED));
        revokedCertificates.add(crlEntry);
        when(certificate.getPublicKey()).thenReturn(ipcsSigningPublicKey);

        when(certificateChainIterator.nextIndex()).thenReturn(1);
        when(certificates.listIterator(1)).thenReturn(issuerCertsIterator);
        when(issuerCertsIterator.hasNext()).thenReturn(true, false);
        when(issuerCertsIterator.next()).thenReturn(certificate);
    }
}
