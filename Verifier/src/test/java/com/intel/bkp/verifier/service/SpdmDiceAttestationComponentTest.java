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

package com.intel.bkp.verifier.service;

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import com.intel.bkp.verifier.interfaces.IDeviceMeasurementsProvider;
import com.intel.bkp.verifier.model.LibConfig;
import com.intel.bkp.verifier.model.LibSpdmParams;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.certificate.DiceChainMeasurementsCollector;
import com.intel.bkp.verifier.service.certificate.SpdmCertificateChainHolder;
import com.intel.bkp.verifier.service.certificate.SpdmChainSearcher;
import com.intel.bkp.verifier.service.certificate.SpdmValidChains;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import com.intel.bkp.verifier.service.measurements.SpdmDeviceMeasurementsRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.Supplier;

import static com.intel.bkp.verifier.service.certificate.DiceChainType.ATTESTATION;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmDiceAttestationComponentTest {

    private static final List<X509Certificate> CERT_CHAIN_FROM_DEVICE = List.of();
    private static final byte[] DEVICE_ID = {1, 2};
    private static final String REF_MEASUREMENT = "aabbccdd";
    private static final List<TcbInfoMeasurement> TCB_INFOS_FROM_CHAIN = List.of(new TcbInfoMeasurement(new TcbInfo()));
    private static final List<TcbInfoMeasurement> TCB_INFOS_FROM_MEASUREMENTS =
        List.of(new TcbInfoMeasurement(new TcbInfo()), new TcbInfoMeasurement(new TcbInfo()));

    private static MockedStatic<AppContext> appContextMockedStatic;

    @Mock
    private AppContext appContextMock;
    @Mock
    private LibConfig libConfigMock;
    @Mock
    private LibSpdmParams libSpdmParamsMock;

    @Mock
    private IDeviceMeasurementsProvider<SpdmDeviceMeasurementsRequest> deviceMeasurementsProvider;
    @Mock
    private EvidenceVerifier evidenceVerifier;
    @Mock
    private TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator;
    @Mock
    private Supplier<TcbInfoMeasurementsAggregator> tcbInfoMeasurementsAggregatorSupplier;
    @Mock
    private DiceChainMeasurementsCollector measurementsCollector;
    @Mock
    private SpdmChainSearcher spdmChainSearcher;
    @Mock
    private SpdmValidChains validChainResponse;

    @InjectMocks
    private SpdmDiceAttestationComponent sut;
    private SpdmCertificateChainHolder ATT_CHAIN =
        new SpdmCertificateChainHolder(1, ATTESTATION, CERT_CHAIN_FROM_DEVICE);

    @BeforeAll
    public static void prepareStaticMock() {
        appContextMockedStatic = mockStatic(AppContext.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        appContextMockedStatic.close();
    }

    @Test
    void perform_RequestSignatureFalse_OnlyMeasurements() throws Exception {
        // given
        mockSkipSignature();

        when(tcbInfoMeasurementsAggregatorSupplier.get()).thenReturn(tcbInfoMeasurementsAggregator);
        when(deviceMeasurementsProvider.getMeasurementsFromDevice(any())).thenReturn(TCB_INFOS_FROM_MEASUREMENTS);

        // when
        sut.perform(REF_MEASUREMENT, DEVICE_ID);

        // then
        verify(spdmChainSearcher, never()).searchValidChains(DEVICE_ID);
        verify(measurementsCollector, never()).getMeasurementsFromCertChain(CERT_CHAIN_FROM_DEVICE);
        verify(tcbInfoMeasurementsAggregator, never()).add(TCB_INFOS_FROM_CHAIN);

        verify(tcbInfoMeasurementsAggregator).add(TCB_INFOS_FROM_MEASUREMENTS);
        verify(evidenceVerifier).verify(tcbInfoMeasurementsAggregator, REF_MEASUREMENT);
    }

    @Test
    void perform_RequestSignatureTrue_GetCertificatesAndMeasurements() throws Exception {
        // given
        mockRequestSignature();

        when(tcbInfoMeasurementsAggregatorSupplier.get()).thenReturn(tcbInfoMeasurementsAggregator);
        when(spdmChainSearcher.searchValidChains(DEVICE_ID)).thenReturn(validChainResponse);
        when(validChainResponse.get(ATTESTATION)).thenReturn(ATT_CHAIN);
        when(measurementsCollector.getMeasurementsFromCertChain(CERT_CHAIN_FROM_DEVICE))
            .thenReturn(TCB_INFOS_FROM_CHAIN);
        when(deviceMeasurementsProvider.getMeasurementsFromDevice(any())).thenReturn(TCB_INFOS_FROM_MEASUREMENTS);

        // when
        sut.perform(REF_MEASUREMENT, DEVICE_ID);

        // then
        verify(measurementsCollector).getMeasurementsFromCertChain(CERT_CHAIN_FROM_DEVICE);
        verify(tcbInfoMeasurementsAggregator).add(TCB_INFOS_FROM_CHAIN);
        verify(tcbInfoMeasurementsAggregator).add(TCB_INFOS_FROM_MEASUREMENTS);
        verify(evidenceVerifier).verify(tcbInfoMeasurementsAggregator, REF_MEASUREMENT);
    }

    private void mockRequestSignature() {
        prepareLibConfig(true);
    }

    private void mockSkipSignature() {
        prepareLibConfig(false);
    }

    private void prepareLibConfig(boolean isRequestSignature) {
        when(AppContext.instance()).thenReturn(appContextMock);
        when(appContextMock.getLibConfig()).thenReturn(libConfigMock);
        when(libConfigMock.getLibSpdmParams()).thenReturn(libSpdmParamsMock);
        when(libSpdmParamsMock.isMeasurementsRequestSignature()).thenReturn(isRequestSignature);
    }
}
