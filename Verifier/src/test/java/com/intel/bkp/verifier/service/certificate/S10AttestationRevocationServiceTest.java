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

package com.intel.bkp.verifier.service.certificate;

import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.core.properties.TrustedRootHash;
import com.intel.bkp.fpgacerts.url.DistributionPointAddressProvider;
import com.intel.bkp.fpgacerts.url.params.S10Params;
import com.intel.bkp.verifier.dp.DistributionPointChainFetcher;
import com.intel.bkp.verifier.dp.DistributionPointConnector;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class S10AttestationRevocationServiceTest {

    private static final String ATTESTATION_CERT_URL = "ATTESTATION_CERT_URL";
    private static final byte[] DEVICE_ID = new byte[]{0x01, 0x02, 0x03};
    private static final String PUF_TYPE = PufType.getPufTypeHex(PufType.EFUSE);

    @Mock
    private X509Certificate attestationCert;

    @Mock
    private X509Certificate parentCert;

    @Mock
    private X509Certificate rootCert;

    @Mock
    private PublicKey attestationPublicKey;

    @Mock
    private S10ChainVerifier s10ChainVerifier;

    @Mock
    private DistributionPointChainFetcher chainFetcher;

    @Mock
    private DistributionPointAddressProvider addressProvider;

    @InjectMocks
    private S10AttestationRevocationService sut;

    @Captor
    private ArgumentCaptor<LinkedList<X509Certificate>> certificatesCaptor;

    @Test
    void constructor_configuresProperly() {
        // given
        final var appContext = mock(AppContext.class);
        final var dpConnector = mock(DistributionPointConnector.class);
        final var certPath = "path";
        final var s10RootHash = "s10";
        final var trustedRootHash = new TrustedRootHash(s10RootHash, "");

        when(appContext.getDpConnector()).thenReturn(dpConnector);
        when(appContext.getDpTrustedRootHash()).thenReturn(trustedRootHash);
        when(appContext.getDpPathCer()).thenReturn(certPath);

        // when
        sut = new S10AttestationRevocationService(appContext);

        // then
        final var s10CertVerifier = sut.getS10ChainVerifier();
        Assertions.assertEquals(s10RootHash, s10CertVerifier.getTrustedRootHash());

        final var crlProvider = s10CertVerifier.getCrlVerifier().getCrlProvider();
        Assertions.assertTrue(crlProvider instanceof DistributionPointCrlProvider);

        final var addressProvider = sut.getAddressProvider();
        Assertions.assertEquals(certPath, addressProvider.getCertificateUrlPrefix());

        verify(appContext, times(2)).getDpConnector();
    }

    @Test
    void checkAndRetrieve_Success() {
        // given
        mockFetchingCertificates(DEVICE_ID, PUF_TYPE);
        mockAttestationKey(attestationPublicKey);

        // when
        final PublicKey result = sut.checkAndRetrieve(DEVICE_ID, PUF_TYPE);

        // then
        Assertions.assertEquals(attestationPublicKey, result);
        verify(s10ChainVerifier).setDeviceId(DEVICE_ID);
        verify(s10ChainVerifier).verifyChain(certificatesCaptor.capture());
        final LinkedList<X509Certificate> certificates = certificatesCaptor.getValue();
        Assertions.assertEquals(attestationCert, certificates.getFirst());
        Assertions.assertEquals(parentCert, certificates.get(1));
        Assertions.assertEquals(rootCert, certificates.getLast());
    }

    @SneakyThrows
    private void mockFetchingCertificates(byte[] deviceId, String pufType) {
        final S10Params expectedParams = S10Params.from(deviceId, pufType);
        when(addressProvider.getAttestationCertUrl(expectedParams)).thenReturn(ATTESTATION_CERT_URL);
        when(chainFetcher.downloadCertificateChain(ATTESTATION_CERT_URL))
            .thenReturn(List.of(attestationCert, parentCert, rootCert));
    }

    private void mockAttestationKey(PublicKey key) {
        when(attestationCert.getPublicKey()).thenReturn(key);
    }
}
