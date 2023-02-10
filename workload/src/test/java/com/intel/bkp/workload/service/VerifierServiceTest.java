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

package com.intel.bkp.workload.service;

import com.intel.bkp.verifier.service.VerifierExchangeImpl;
import com.intel.bkp.verifier.service.dto.VerifierExchangeResponseDTO;
import com.intel.bkp.workload.exceptions.WorkloadAppException;
import com.intel.bkp.workload.model.CommandType;
import com.intel.bkp.workload.util.AppArgument;
import com.intel.bkp.workload.util.WorkloadFileReader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VerifierServiceTest {

    @Mock
    WorkloadFileReader fileReader;

    @Mock
    VerifierExchangeImpl verifierExchange;

    VerifierService sut;

    final String transportId = "host:127.0.0.1; port:80; cableID:999";

    @BeforeEach
    void setUp() {
        sut = spy(new VerifierService());
        doReturn(verifierExchange).when(sut).getVerifierExchange();
    }

    @Test
    void callVerifier_WithCreateCommand_Success() {
        // given
        final String context = "0102";
        final String pufType = "EFUSE";

        AppArgument appArgument = AppArgument
            .instance()
            .command(CommandType.CREATE.name())
            .context(context)
            .transportId(transportId)
            .pufType(pufType)
            .build();

        // when
        sut.callVerifier(appArgument);

        // then
        Mockito.verify(verifierExchange).createDeviceAttestationSubKey(transportId, context, pufType);
    }

    @Test
    void callVerifier_WithHealthCommand_Success() {
        // given

        AppArgument appArgument = AppArgument
            .instance()
            .command(CommandType.HEALTH.name())
            .transportId(transportId)
            .build();

        // when
        sut.callVerifier(appArgument);

        // then
        Mockito.verify(verifierExchange).healthCheck(transportId);
    }

    @Test
    void callVerifier_WithGetCommand_Success() {
        // given
        final String refMeasurementFile = "test_file";
        final String refMeasurementContent = "test_content";
        doReturn(fileReader).when(sut).getFileReader();
        when(fileReader.exists(refMeasurementFile)).thenReturn(true);
        when(fileReader.readFile(refMeasurementFile)).thenReturn(refMeasurementContent);
        when(verifierExchange.getDeviceAttestation(transportId, refMeasurementContent))
            .thenReturn(new VerifierExchangeResponseDTO());

        AppArgument appArgument = AppArgument
            .instance()
            .command(CommandType.GET.name())
            .refMeasurement(refMeasurementFile)
            .transportId(transportId)
            .build();

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.callVerifier(appArgument));
    }

    @Test
    void callVerifier_WithGetCommand_EvidenceFileDoesNotExist() {
        // given
        final int transportId = 999;
        final String refMeasurementFile = "test_file";
        doReturn(fileReader).when(sut).getFileReader();
        when(fileReader.exists(refMeasurementFile)).thenReturn(false);

        AppArgument appArgument = AppArgument
            .instance()
            .command(CommandType.GET.name())
            .refMeasurement(refMeasurementFile)
            .transportId(String.valueOf(transportId))
            .build();

        // when-then
        Assertions.assertThrows(WorkloadAppException.class, () -> sut.callVerifier(appArgument));
    }

    @Test
    void callVerifier_WithMissingCommandType_ThrowsException() {
        // given
        AppArgument appArgument = new AppArgument();

        // when
        Assertions.assertThrows(WorkloadAppException.class, () -> sut.callVerifier(appArgument));
    }

    @Test
    void callVerifier_WithMissingRequiredArgsForCommand_ThrowsException() {
        // given
        AppArgument appArgument = AppArgument
            .instance()
            .command(CommandType.CREATE.name())
            .build();

        // when
        Assertions.assertThrows(WorkloadAppException.class, () -> sut.callVerifier(appArgument));
    }
}
