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

package com.intel.bkp.verifier.service.measurements;

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.verifier.command.responses.attestation.SpdmMeasurementResponse;
import com.intel.bkp.verifier.exceptions.SpdmCommandFailedException;
import com.intel.bkp.verifier.interfaces.IMeasurementResponseToTcbInfoMapper;
import com.intel.bkp.verifier.service.sender.SpdmGetMeasurementMessageSender;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmDeviceMeasurementsProviderTest {

    private static final int SLOT_ID = 2;
    private final List<TcbInfoMeasurement> expectedResult = List.of(new TcbInfoMeasurement(new TcbInfo()));

    @Mock
    private SpdmDeviceMeasurementsRequest spdmDeviceMeasurementsRequest;
    @Mock
    private SpdmMeasurementResponse spdmMeasurementResponse;
    @Mock
    private SpdmGetMeasurementMessageSender spdmGetMeasurementMessageSender;
    @Mock
    private IMeasurementResponseToTcbInfoMapper<SpdmMeasurementResponse> measurementResponseMapper;

    @InjectMocks
    private SpdmDeviceMeasurementsProvider sut;

    @Test
    void getMeasurementsFromDevice_CallsMapper_ReturnsListOfTcbInfos() throws SpdmCommandFailedException {
        // given
        when(spdmDeviceMeasurementsRequest.slotId()).thenReturn(SLOT_ID);
        when(spdmGetMeasurementMessageSender.send(SLOT_ID)).thenReturn(spdmMeasurementResponse);
        when(measurementResponseMapper.map(spdmMeasurementResponse)).thenReturn(expectedResult);

        // when
        final List<TcbInfoMeasurement> result = sut.getMeasurementsFromDevice(spdmDeviceMeasurementsRequest);

        // then
        assertEquals(expectedResult, result);
    }
}
