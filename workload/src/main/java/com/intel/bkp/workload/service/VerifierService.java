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

package com.intel.bkp.workload.service;

import com.intel.bkp.verifier.interfaces.VerifierExchange;
import com.intel.bkp.verifier.model.dto.VerifierExchangeResponseDTO;
import com.intel.bkp.verifier.service.VerifierExchangeImpl;
import com.intel.bkp.workload.exceptions.WorkloadAppException;
import com.intel.bkp.workload.model.CommandType;
import com.intel.bkp.workload.util.AppArgument;
import com.intel.bkp.workload.util.WorkloadFileReader;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class VerifierService {

    private static final String NOT_SUPPORTED_COMMAND_TYPE = "Not supported command type";
    private static final String INVALID_REF_MEASUREMENT
        = "Provide valid --ref-measurement parameter to invoke GET command.";
    private static final String INVALID_CONTEXT = "Provide valid --context parameter to invoke CREATE command.";
    private static final String INVALID_PUF_TYPE = "Provide valid --puf-type parameter to invoke CREATE command.";

    public int callVerifier(AppArgument appArgs) {
        return perform(appArgs, getVerifierExchange());
    }

    WorkloadFileReader getFileReader() {
        return new WorkloadFileReader();
    }

    VerifierExchangeImpl getVerifierExchange() {
        return new VerifierExchangeImpl();
    }

    private int perform(AppArgument appArgs, VerifierExchange verifierExchange) {
        verifyParam(appArgs.getCommand() != null, NOT_SUPPORTED_COMMAND_TYPE);

        return getPerformCommandMethod(appArgs.getCommand())
            .performCommand(appArgs, verifierExchange);
    }

    private IPerformCommand getPerformCommandMethod(CommandType commandType) {
        return switch (commandType) {
            case GET -> this::performGet;
            case CREATE -> this::performCreate;
            case HEALTH -> this::performHealth;
        };
    }

    interface IPerformCommand {

        int performCommand(AppArgument appArgs, VerifierExchange verifierExchange);
    }

    private int performGet(AppArgument appArgs, VerifierExchange verifierExchange) {
        final WorkloadFileReader fileReader = getFileReader();
        final String refMeasurementFilePath = appArgs.getRefMeasurement();

        verifyParam(refMeasurementFilePath != null
            && fileReader.exists(refMeasurementFilePath), INVALID_REF_MEASUREMENT);

        final VerifierExchangeResponseDTO result = verifierExchange.getDeviceAttestation(
            appArgs.getTransportId(), fileReader.readFile(refMeasurementFilePath));
        final int returnCode = result.getStatus();
        log.info("[WORKLOAD] Get device attestation result for deviceId {}: {}", result.getDeviceId(),
            returnCode);
        return returnCode;
    }

    private int performCreate(AppArgument appArgs, VerifierExchange verifierExchange) {
        verifyParam(appArgs.getContext() != null, INVALID_CONTEXT);
        verifyParam(appArgs.getPufType() != null, INVALID_PUF_TYPE);

        final int returnCode = verifierExchange.createDeviceAttestationSubKey(
            appArgs.getTransportId(), appArgs.getContext(), appArgs.getPufType());
        log.info("[WORKLOAD] Creating device attestation subkey result: {}", returnCode);
        return returnCode;
    }

    private int performHealth(AppArgument appArgs, VerifierExchange verifierExchange) {
        final int returnCode = verifierExchange.healthCheck(appArgs.getTransportId());
        log.info("[WORKLOAD] Health check result: {}", returnCode);
        return returnCode;
    }

    private void verifyParam(boolean isValid, String errorMsg) {
        if (!isValid) {
            throw new WorkloadAppException(errorMsg);
        }
    }
}
