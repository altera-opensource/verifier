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

import com.intel.bkp.ext.core.certificate.X509CertificateUtils;
import com.intel.bkp.ext.core.manufacturing.model.PufType;
import com.intel.bkp.verifier.dp.DistributionPointConnector;
import com.intel.bkp.verifier.dp.ProxyCallbackFactory;
import com.intel.bkp.verifier.interfaces.IProxyCallback;
import com.intel.bkp.verifier.model.DistributionPoint;
import com.intel.bkp.verifier.model.LibConfig;
import com.intel.bkp.verifier.model.Proxy;
import com.intel.bkp.verifier.model.TrustedRootHash;
import com.intel.bkp.verifier.model.s10.S10Params;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class S10AttestationRevocationServiceTest {

    private static final String ATTESTATION_CERT_URL = "ATTESTATION_CERT_URL";
    private static final String PARENT_CERT_URL = "PARENT_CERT_URL";
    private static final String ROOT_CERT_URL = "ROOT_CERT_URL";
    private static final byte[] ATTESTATION_CERT_BYTES = new byte[]{0x01, 0x01, 0x01};
    private static final byte[] PARENT_CERT_BYTES = new byte[]{0x02, 0x02, 0x02};
    private static final byte[] ROOT_CERT_BYTES = new byte[]{0x03, 0x03, 0x03};
    private static final byte[] DEVICE_ID = new byte[]{0x01, 0x02, 0x03};
    private static final String PUF_TYPE = PufType.getPufTypeHex(PufType.EFUSE);

    private static MockedStatic<X509CertificateUtils> x509CertificateUtilsMockStatic;

    private static MockedStatic<ProxyCallbackFactory> proxyFactoryMockStatic;

    @Mock
    private X509Certificate attestationCert;

    @Mock
    private X509Certificate parentCert;

    @Mock
    private X509Certificate rootCert;

    @Mock
    private PublicKey attestationPublicKey;

    @Mock
    private X509CertificateParser certificateParser;

    @Mock
    private S10CertificateVerifier s10CertificateVerifier;

    @Mock
    private DistributionPointConnector connector;

    @Mock
    private DistributionPointAddressProvider addressProvider;

    @InjectMocks
    private S10AttestationRevocationService sut;

    @Captor
    private ArgumentCaptor<LinkedList<X509Certificate>> certificatesCaptor;

    @BeforeAll
    public static void prepareStaticMock() {
        x509CertificateUtilsMockStatic = mockStatic(X509CertificateUtils.class);
        proxyFactoryMockStatic = mockStatic(ProxyCallbackFactory.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        x509CertificateUtilsMockStatic.close();
        proxyFactoryMockStatic.close();
    }

    @Test
    void constructor_configuresProperly() {
        // given
        final var appContext = mock(AppContext.class);
        final var libConfig = mock(LibConfig.class);
        final var dp = mock(DistributionPoint.class);
        final var certPath = "path";
        final var trustedRootHash = new TrustedRootHash("s10", "dice");
        final var host = "host";
        final var port = 123;
        final var proxy = new Proxy(host, port);
        final var proxyCallback = mock(IProxyCallback.class);

        when(appContext.getLibConfig()).thenReturn(libConfig);
        when(libConfig.getDistributionPoint()).thenReturn(dp);
        when(dp.getPathCer()).thenReturn(certPath);
        when(dp.getTrustedRootHash()).thenReturn(trustedRootHash);
        when(dp.getProxy()).thenReturn(proxy);
        when(ProxyCallbackFactory.get(host, port)).thenReturn(proxyCallback);

        // when
        sut = new S10AttestationRevocationService(appContext);

        // then
        final var s10CertVerifier = sut.getS10CertificateVerifier();
        Assertions.assertEquals(trustedRootHash, s10CertVerifier.getTrustedRootHash());

        final var crlProvider = s10CertVerifier.getCrlVerifier().getCrlProvider();
        Assertions.assertTrue(crlProvider instanceof DistributionPointCrlProvider);

        final var addressProvider = sut.getAddressProvider();
        Assertions.assertEquals(certPath, addressProvider.getCertificateUrlPrefix());

        proxyFactoryMockStatic.verify(() -> ProxyCallbackFactory.get(host, port), times(2));
    }

    @Test
    void checkAndRetrieve_Success() {
        // given
        mockFetchingCertificates(DEVICE_ID, PUF_TYPE);
        mockAttestationKey(attestationPublicKey);
        when(s10CertificateVerifier.withDevice(DEVICE_ID)).thenReturn(s10CertificateVerifier);

        // when
        final PublicKey result = sut.checkAndRetrieve(DEVICE_ID, PUF_TYPE);

        // then
        Assertions.assertEquals(attestationPublicKey, result);
        verify(s10CertificateVerifier).verify(certificatesCaptor.capture());
        final LinkedList<X509Certificate> certificates = certificatesCaptor.getValue();
        Assertions.assertEquals(attestationCert, certificates.getFirst());
        Assertions.assertEquals(parentCert, certificates.get(1));
        Assertions.assertEquals(rootCert, certificates.getLast());
    }

    private void mockFetchingCertificates(byte[] deviceId, String pufType) {
        final S10Params expectedParams = S10Params.from(deviceId, pufType);
        when(addressProvider.getAttestationCertFilename(expectedParams)).thenReturn(ATTESTATION_CERT_URL);

        when(connector.getBytes(ATTESTATION_CERT_URL)).thenReturn(ATTESTATION_CERT_BYTES);
        when(certificateParser.toX509(ATTESTATION_CERT_BYTES)).thenReturn(attestationCert);
        when(X509CertificateUtils.isSelfSigned(attestationCert)).thenReturn(false);
        when(certificateParser.getPathToIssuerCertificate(attestationCert)).thenReturn(PARENT_CERT_URL);

        when(connector.getBytes(PARENT_CERT_URL)).thenReturn(PARENT_CERT_BYTES);
        when(certificateParser.toX509(PARENT_CERT_BYTES)).thenReturn(parentCert);
        when(X509CertificateUtils.isSelfSigned(parentCert)).thenReturn(false);
        when(certificateParser.getPathToIssuerCertificate(parentCert)).thenReturn(ROOT_CERT_URL);

        when(connector.getBytes(ROOT_CERT_URL)).thenReturn(ROOT_CERT_BYTES);
        when(certificateParser.toX509(ROOT_CERT_BYTES)).thenReturn(rootCert);
        when(X509CertificateUtils.isSelfSigned(rootCert)).thenReturn(true);
    }

    private void mockAttestationKey(PublicKey key) {
        when(attestationCert.getPublicKey()).thenReturn(key);
    }
}
