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

package com.intel.bkp.verifier.protocol.sigma.service;

import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.sigma.GetMeasurementResponse;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import com.intel.bkp.verifier.protocol.sigma.model.RootChainType;
import com.intel.bkp.verifier.protocol.sigma.verification.GetMeasurementVerifier;
import com.intel.bkp.verifier.protocol.sigma.verification.SigmaM2DeviceIdVerifier;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.transport.model.TransportLayer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GpDeviceMeasurementsProviderTest {

    private static final byte[] DEVICE_ID = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
    private static final byte[] DEVICE_ID_INCOMING = new byte[]{2, 4, 1, 3, 5, 6, 7, 8};
    private static final RootChainType ROOT_CHAIN_TYPE = RootChainType.SINGLE;
    private static final PufType PUF_TYPE = PufType.EFUSE;
    private static final String CONTEXT = "context";
    private static final int COUNTER = 3;
    private static final byte[] SDM_SESSION_ID = {0, 0, 0, 1};

    private static MockedStatic<EcdhKeyPair> ecdhKeyPairMockStatic;

    @Mock
    private CommandLayer commandLayer;

    @Mock
    private TransportLayer transportLayer;

    @Mock
    private GetMeasurementMessageSender getMeasurementMessageSender;

    @Mock
    private TeardownMessageSender teardownMessageSender;

    @Mock
    private GetMeasurementVerifier getMeasurementVerifier;

    @Mock
    private SigmaM2DeviceIdVerifier deviceIdVerifier;

    @Mock
    private GpMeasurementResponseToTcbInfoMapper measurementMapper;

    @Mock
    private GetMeasurementResponse response;

    @Mock
    private PublicKey aliasPubKey;

    @Mock
    private EcdhKeyPair ecdhKeyPair;

    @Mock
    private List<TcbInfoMeasurement> measurements;

    @InjectMocks
    private GpDeviceMeasurementsProvider sut;

    @BeforeAll
    public static void prepareStaticMock() {
        ecdhKeyPairMockStatic = mockStatic(EcdhKeyPair.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        ecdhKeyPairMockStatic.close();
    }

    @Test
    void constructor_doesNotThrow() {
        // given
        final var appContext = mock(AppContext.class);

        // then
        assertDoesNotThrow(() -> new GpDeviceMeasurementsProvider(appContext));
    }

    @Test
    void getMeasurementsFromDevice_Success() throws EcdhKeyPairException {
        // given
        final var request = prepareRequest();
        when(EcdhKeyPair.generate()).thenReturn(ecdhKeyPair);
        mockGetMeasurementResponse(DEVICE_ID_INCOMING, SDM_SESSION_ID);
        mockGetMeasurementMessageSender();
        when(measurementMapper.map(any())).thenReturn(measurements);

        // when
        final var result = sut.getMeasurementsFromDevice(request);

        // then
        assertEquals(measurements, result);
        verify(getMeasurementVerifier).verify(aliasPubKey, response, ecdhKeyPair);
        verify(deviceIdVerifier).verify(DEVICE_ID, DEVICE_ID_INCOMING);
        verify(teardownMessageSender).send(transportLayer, commandLayer, SDM_SESSION_ID);
    }

    @Test
    void getMeasurementsFromDevice_failsToGenerateEcdhKeyPair_Throws() throws EcdhKeyPairException {
        // given
        final var request = prepareRequest();
        when(EcdhKeyPair.generate()).thenThrow(new EcdhKeyPairException(""));

        // when-then
        assertThrows(InternalLibraryException.class, () -> sut.getMeasurementsFromDevice(request));
    }

    private void mockGetMeasurementMessageSender() {
        when(getMeasurementMessageSender.withChainType(ROOT_CHAIN_TYPE)).thenReturn(getMeasurementMessageSender);
        when(getMeasurementMessageSender.send(transportLayer, commandLayer, ecdhKeyPair, PUF_TYPE, CONTEXT, COUNTER))
            .thenReturn(response);
    }

    private void mockGetMeasurementResponse(byte[] deviceId, byte[] sdmSessionId) {
        when(response.getDeviceUniqueId()).thenReturn(deviceId);
        when(response.getSdmSessionId()).thenReturn(sdmSessionId);
    }

    private GpDeviceMeasurementsRequest prepareRequest() {
        return new GpDeviceMeasurementsRequest(DEVICE_ID, ROOT_CHAIN_TYPE, aliasPubKey, PUF_TYPE, CONTEXT, COUNTER);
    }
}
