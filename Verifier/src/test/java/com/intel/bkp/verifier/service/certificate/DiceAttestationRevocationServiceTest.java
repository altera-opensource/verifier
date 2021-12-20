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

import com.intel.bkp.verifier.dp.DistributionPointConnector;
import com.intel.bkp.verifier.dp.ProxyCallbackFactory;
import com.intel.bkp.verifier.interfaces.IProxyCallback;
import com.intel.bkp.verifier.model.DistributionPoint;
import com.intel.bkp.verifier.model.LibConfig;
import com.intel.bkp.verifier.model.Proxy;
import com.intel.bkp.verifier.model.TrustedRootHash;
import com.intel.bkp.verifier.model.dice.DiceEnrollmentParams;
import com.intel.bkp.verifier.model.dice.DiceParams;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiceAttestationRevocationServiceTest {

    private static final String DEVICE_ID_NAME = "DEVICE_ID_NAME";
    private static final String ENROLLMENT_NAME = "ENROLLMENT_NAME";
    private static final String IID_NAME = "IID_NAME";
    private static final Optional<byte[]> EMPTY_CERT = Optional.empty();
    private static final byte[] NOT_EMPTY_CERT = new byte[]{};
    private static final DiceParams DICE_PARAMS = new DiceParams("SKI", "UID");
    private static final DiceEnrollmentParams DICE_ENROLLMENT_PARAMS = new DiceEnrollmentParams("SKIER", "SVN", "UID");

    private static MockedStatic<ProxyCallbackFactory> proxyFactoryMockStatic;

    @Mock
    private X509Certificate certificate;

    @Mock
    private DistributionPointConnector connector;

    @Mock
    private DiceCertificateVerifier diceCertificateVerifier;

    @Mock
    private X509CertificateParser certificateParser;

    @Mock
    private DistributionPointAddressProvider addressProvider;

    @InjectMocks
    private DiceAttestationRevocationService sut;

    @BeforeAll
    public static void prepareStaticMock() {
        proxyFactoryMockStatic = mockStatic(ProxyCallbackFactory.class);
    }

    @AfterAll
    public static void closeStaticMock() {
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
        sut = new DiceAttestationRevocationService(appContext);

        // then
        final var diceCertVerifier = sut.getDiceCertificateVerifier();
        Assertions.assertEquals(trustedRootHash, diceCertVerifier.getTrustedRootHash());

        final var crlProvider = diceCertVerifier.getCrlVerifier().getCrlProvider();
        Assertions.assertTrue(crlProvider instanceof DistributionPointCrlProvider);

        final var addressProvider = sut.getAddressProvider();
        Assertions.assertEquals(certPath, addressProvider.getCertificateUrlPrefix());

        proxyFactoryMockStatic.verify(() -> ProxyCallbackFactory.get(host, port), times(2));
    }

    @Test
    void fmGetDeviceIdCert_WithEmpty() {
        // given
        when(addressProvider.getDeviceIdCertFilename(DICE_PARAMS)).thenReturn(DEVICE_ID_NAME);
        when(connector.tryGetBytes(DEVICE_ID_NAME)).thenReturn(EMPTY_CERT);

        // when
        final Optional<X509Certificate> result = sut.fmGetDeviceIdCert(DICE_PARAMS);

        // then
        Assertions.assertTrue(result.isEmpty());
    }

    @Test
    void fmGetDeviceIdCert_ReturnsCert() {
        // given
        when(addressProvider.getDeviceIdCertFilename(DICE_PARAMS)).thenReturn(DEVICE_ID_NAME);
        when(connector.tryGetBytes(DEVICE_ID_NAME)).thenReturn(Optional.of(NOT_EMPTY_CERT));
        when(certificateParser.toX509(NOT_EMPTY_CERT)).thenReturn(certificate);

        // when
        final Optional<X509Certificate> result = sut.fmGetDeviceIdCert(DICE_PARAMS);

        // then
        Assertions.assertTrue(result.isPresent());
        Assertions.assertEquals(certificate, result.get());
    }

    @Test
    void fmGetEnrollmentCert_WithEmpty() {
        // given
        when(addressProvider.getEnrollmentCertFilename(DICE_ENROLLMENT_PARAMS))
            .thenReturn(ENROLLMENT_NAME);
        when(connector.tryGetBytes(ENROLLMENT_NAME)).thenReturn(EMPTY_CERT);

        // when
        final Optional<X509Certificate> result = sut.fmGetEnrollmentCert(DICE_ENROLLMENT_PARAMS);

        // then
        Assertions.assertTrue(result.isEmpty());
    }

    @Test
    void fmGetEnrollmentCert_ReturnsCert() {
        // given
        when(addressProvider.getEnrollmentCertFilename(DICE_ENROLLMENT_PARAMS)).
            thenReturn(ENROLLMENT_NAME);
        when(connector.tryGetBytes(ENROLLMENT_NAME)).thenReturn(Optional.of(NOT_EMPTY_CERT));
        when(certificateParser.toX509(NOT_EMPTY_CERT)).thenReturn(certificate);

        // when
        final Optional<X509Certificate> result = sut.fmGetEnrollmentCert(DICE_ENROLLMENT_PARAMS);

        // then
        Assertions.assertTrue(result.isPresent());
        Assertions.assertEquals(certificate, result.get());
    }

    @Test
    void fmGetIidUdsCert_WithEmpty() {
        // given
        when(addressProvider.getIidUdsCertFilename(DICE_PARAMS)).thenReturn(IID_NAME);
        when(connector.tryGetBytes(IID_NAME)).thenReturn(EMPTY_CERT);

        // when
        final Optional<X509Certificate> result = sut.fmGetIidUdsCert(DICE_PARAMS);

        // then
        Assertions.assertTrue(result.isEmpty());
    }

    @Test
    void fmGetIidUdsCert_ReturnsCert() {
        // given
        when(addressProvider.getIidUdsCertFilename(DICE_PARAMS)).thenReturn(IID_NAME);
        when(connector.tryGetBytes(IID_NAME)).thenReturn(Optional.of(NOT_EMPTY_CERT));
        when(certificateParser.toX509(NOT_EMPTY_CERT)).thenReturn(certificate);

        // when
        final Optional<X509Certificate> result = sut.fmGetIidUdsCert(DICE_PARAMS);

        // then
        Assertions.assertTrue(result.isPresent());
        Assertions.assertEquals(certificate, result.get());
    }
}
