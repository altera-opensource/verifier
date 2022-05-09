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

import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoAggregator;
import com.intel.bkp.verifier.database.SQLiteHelper;
import com.intel.bkp.verifier.database.model.S10CacheEntity;
import com.intel.bkp.verifier.database.repository.S10CacheEntityService;
import com.intel.bkp.verifier.exceptions.CacheEntityDoesNotExistException;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.certificate.S10AttestationRevocationService;
import com.intel.bkp.verifier.service.measurements.DeviceMeasurementsProvider;
import com.intel.bkp.verifier.service.measurements.DeviceMeasurementsRequest;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class S10AttestationComponentTest {

    private static final String REF_MEASUREMENT = "0102";
    private static final byte[] DEVICE_ID = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

    private static MockedStatic<DeviceMeasurementsRequest> deviceMeasurementsRequestMockStatic;

    @Mock
    private AppContext appContext;

    @Mock
    private SQLiteHelper sqLiteHelper;

    @Mock
    private S10CacheEntity cacheEntity;

    @Mock
    private EvidenceVerifier evidenceVerifier;

    @Mock
    private S10AttestationRevocationService s10AttestationRevocationService;

    @Mock
    private S10CacheEntityService s10CacheEntityService;

    @Mock
    private DeviceMeasurementsRequest deviceMeasurementsRequest;

    @Mock
    private DeviceMeasurementsProvider deviceMeasurementsProvider;

    @Mock
    private List<TcbInfo> measurements;

    @Mock
    private TcbInfoAggregator tcbInfoAggregator;

    @InjectMocks
    private S10AttestationComponent sut;

    @BeforeAll
    public static void prepareStaticMock() {
        deviceMeasurementsRequestMockStatic = mockStatic(DeviceMeasurementsRequest.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        deviceMeasurementsRequestMockStatic.close();
    }

    @Test
    void perform_Success() {
        // given
        final var pufType = PufType.IID;
        mockEntityInDatabase(DEVICE_ID, pufType);
        when(DeviceMeasurementsRequest.forS10(DEVICE_ID, cacheEntity)).thenReturn(deviceMeasurementsRequest);
        when(deviceMeasurementsProvider.getMeasurementsFromDevice(deviceMeasurementsRequest)).thenReturn(measurements);
        when(evidenceVerifier.verify(eq(tcbInfoAggregator), eq(REF_MEASUREMENT))).thenReturn
            (VerifierExchangeResponse.OK);

        // when
        VerifierExchangeResponse result = sut.perform(appContext, REF_MEASUREMENT, DEVICE_ID);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.OK, result);
        verify(s10AttestationRevocationService).checkAndRetrieve(DEVICE_ID, PufType.getPufTypeHex(pufType));
        verify(tcbInfoAggregator).add(measurements);
    }

    @Test
    void perform_EntityDoesNotExist() {
        // given
        mockEmptyDatabase();

        // when-then
        Assertions.assertThrows(CacheEntityDoesNotExistException.class,
            () -> sut.perform(appContext, REF_MEASUREMENT, DEVICE_ID));
    }

    private void mockEntityInDatabase(byte[] deviceId, PufType pufType) {
        mockSqliteHelper();
        when(s10CacheEntityService.read(deviceId)).thenReturn(Optional.of(cacheEntity));
        when(cacheEntity.getPufType()).thenReturn(pufType.name());
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
