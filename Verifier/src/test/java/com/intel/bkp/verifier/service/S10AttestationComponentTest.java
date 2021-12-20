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

package com.intel.bkp.verifier.service;

import com.intel.bkp.ext.core.manufacturing.model.PufType;
import com.intel.bkp.ext.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponseBuilder;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponseToTcbInfoMapper;
import com.intel.bkp.verifier.database.SQLiteHelper;
import com.intel.bkp.verifier.database.model.S10CacheEntity;
import com.intel.bkp.verifier.database.repository.S10CacheEntityService;
import com.intel.bkp.verifier.exceptions.CacheEntityDoesNotExistException;
import com.intel.bkp.verifier.interfaces.CommandLayer;
import com.intel.bkp.verifier.interfaces.TransportLayer;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.model.dice.TcbInfoAggregator;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.certificate.S10AttestationRevocationService;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import com.intel.bkp.verifier.service.sender.GetMeasurementMessageSender;
import com.intel.bkp.verifier.service.sender.TeardownMessageSender;
import com.intel.bkp.verifier.sigma.GetMeasurementVerifier;
import com.intel.bkp.verifier.sigma.SigmaM2DeviceIdVerifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class S10AttestationComponentTest {

    private static final String REF_MEASUREMENT = "0102";
    private static final byte[] DEVICE_ID = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
    private static final byte[] SDM_SESSION_ID = { 0, 0, 0, 1 };

    @Mock
    private AppContext appContext;

    @Mock
    private SQLiteHelper sqLiteHelper;

    @Mock
    private S10CacheEntity cacheEntity;

    @Mock
    private CommandLayer commandLayer;

    @Mock
    private TransportLayer transportLayer;

    @Mock
    private GetMeasurementResponseToTcbInfoMapper measurementMapper;

    @Mock
    private GetMeasurementMessageSender getMeasurementMessageSender;

    @Mock
    private TeardownMessageSender teardownMessageSender;

    @Mock
    private GetMeasurementVerifier getMeasurementVerifier;

    @Mock
    private EvidenceVerifier evidenceVerifier;

    @Mock
    private S10AttestationRevocationService s10AttestationRevocationService;

    @Mock
    private S10CacheEntityService s10CacheEntityService;

    @Mock
    private SigmaM2DeviceIdVerifier deviceIdVerifier;

    @Mock
    private TcbInfoAggregator tcbInfoAggregator;

    @InjectMocks
    private S10AttestationComponent sut;

    private GetMeasurementResponseBuilder getMeasurementResponseBuilder =
        new GetMeasurementResponseBuilder();

    @Test
    void perform_Success() {
        // given
        mockAppContext();
        mockDatabaseConnection();

        getMeasurementResponseBuilder.setSdmSessionId(SDM_SESSION_ID);
        doReturn(getMeasurementResponseBuilder.build())
            .when(getMeasurementMessageSender)
            .send(eq(transportLayer), eq(commandLayer), any(EcdhKeyPair.class), eq(cacheEntity));
        when(evidenceVerifier.verify(eq(tcbInfoAggregator), eq(REF_MEASUREMENT))).thenReturn(VerifierExchangeResponse.OK);

        // when
        VerifierExchangeResponse result = sut.perform(appContext, REF_MEASUREMENT, DEVICE_ID);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.OK, result);
        verify(s10AttestationRevocationService).checkAndRetrieve(DEVICE_ID,
            PufType.getPufTypeHex(PufType.IID));
        verify(getMeasurementVerifier).verify(any(), any(), eq(cacheEntity));
        verify(deviceIdVerifier).verify(eq(DEVICE_ID), any());
        verify(teardownMessageSender).send(transportLayer, commandLayer, SDM_SESSION_ID);
    }

    @Test
    void perform_EntityDoesNotExist() {
        // given
        mockAppContext();
        mockEmptyDatabase();

        // when-then
        Assertions.assertThrows(CacheEntityDoesNotExistException.class,
            () -> sut.perform(appContext, REF_MEASUREMENT, DEVICE_ID));
    }

    private void mockAppContext() {
        when(appContext.getTransportLayer()).thenReturn(transportLayer);
        when(appContext.getCommandLayer()).thenReturn(commandLayer);
    }

    private void mockDatabaseConnection() {
        mockSqliteHelper();
        when(s10CacheEntityService.read(DEVICE_ID)).thenReturn(Optional.of(cacheEntity));
        when(cacheEntity.getPufType()).thenReturn("IID");
    }

    private void mockEmptyDatabase() {
        mockSqliteHelper();
        when(s10CacheEntityService.read(DEVICE_ID)).thenReturn(Optional.empty());
    }

    private void mockSqliteHelper() {
        when(appContext.getSqLiteHelper()).thenReturn(sqLiteHelper);
        when(sqLiteHelper.getS10CacheEntityService()).thenReturn(s10CacheEntityService);
    }
}
