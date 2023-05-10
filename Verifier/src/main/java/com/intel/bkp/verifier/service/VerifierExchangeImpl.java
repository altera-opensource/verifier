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

package com.intel.bkp.verifier.service;

import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.verifier.exceptions.VerifierKeyNotInitializedException;
import com.intel.bkp.verifier.interfaces.TransportLayer;
import com.intel.bkp.verifier.interfaces.VerifierExchange;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.dto.VerifierExchangeResponseDTO;
import com.intel.bkp.verifier.validators.ParameterValidator;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import static com.intel.bkp.utils.HexConverter.toHex;
import static com.intel.bkp.verifier.model.VerifierExchangeResponse.ERROR;
import static com.intel.bkp.verifier.model.VerifierExchangeResponse.OK;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class VerifierExchangeImpl implements VerifierExchange {

    private static final byte[] GET_CHIPID = new byte[]{0x12, 0x00, 0x00, 0x00};

    private final ParameterValidator parameterValidator = new ParameterValidator();

    private final InitSessionComponent initSessionComponent;
    private final CreateDeviceAttestationSubKeyComponent createSubKeyComponent;
    private final GetDeviceAttestationComponent getAttestationComponent;

    public VerifierExchangeImpl() {
        this(new InitSessionComponent(), new CreateDeviceAttestationSubKeyComponent(),
            new GetDeviceAttestationComponent());
    }

    @Override
    @SuppressWarnings("unchecked")
    public int createDeviceAttestationSubKey(String transportId, String context, String pufType) {
        try (AppContext appContext = AppContext.instance()) {
            appContext.init();
            return createSubKeyInternal(appContext, transportId, context, PufType.valueOf(pufType));
        } catch (Exception e) {
            log.error("Create attestation subkey failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return ERROR.getCode();
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public VerifierExchangeResponseDTO getDeviceAttestation(String transportId, String refMeasurement) {
        var attestationResult = new VerifierExchangeResponseDTO(ERROR.getCode(), "");

        try (AppContext appContext = AppContext.instance()) {
            appContext.init();
            attestationResult = getAttestationInternal(appContext, transportId, refMeasurement);
        } catch (Exception e) {
            log.error("Device attestation failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
        }

        logAttestationResult(attestationResult);

        return attestationResult;
    }

    @Override
    @SuppressWarnings("unchecked")
    public int healthCheck(String transportId) {
        try (AppContext appContext = AppContext.instance()) {
            appContext.init();
            return healthCheckInternal(appContext, transportId);
        } catch (VerifierKeyNotInitializedException e) {
            log.info(e.getMessage());
            return ERROR.getCode();
        } catch (Exception e) {
            log.error("Health check failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return ERROR.getCode();
        }
    }

    int createSubKeyInternal(AppContext appContext, String transportId, String context, PufType pufType) {
        // this check is required to prevent SQL Injection
        if (!parameterValidator.validateContext(context)) {
            return ERROR.getCode();
        }

        final TransportLayer transportLayer = appContext.getTransportLayer();
        try {
            transportLayer.initialize(transportId);
            final byte[] deviceId = initSessionComponent.initializeSessionForDeviceId();
            log.info("Creating attestation subkey will be performed for device of id: {}", toHex(deviceId));

            return createSubKeyComponent.perform(context, pufType, deviceId).getCode();
        } catch (Exception e) {
            log.error("Failed to perform creating of attestation subkey: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return ERROR.getCode();
        } finally {
            transportLayer.disconnect();
        }
    }

    VerifierExchangeResponseDTO getAttestationInternal(
        AppContext appContext, String transportId, String refMeasurement) {
        final VerifierExchangeResponseDTO response = new VerifierExchangeResponseDTO();

        final TransportLayer transportLayer = appContext.getTransportLayer();
        try {
            transportLayer.initialize(transportId);
            final byte[] deviceId = initSessionComponent.initializeSessionForDeviceId();
            response.setDeviceId(toHex(deviceId));
            log.info("Platform attestation will be performed for device of id: {}", toHex(deviceId));

            response.setStatus(getAttestationComponent.perform(refMeasurement, deviceId).getCode());
        } catch (Exception e) {
            log.error("Failed to perform platform attestation: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            response.setStatus(ERROR.getCode());
        } finally {
            transportLayer.disconnect();
        }
        return response;
    }

    int healthCheckInternal(AppContext appContext, String transportId) {
        final TransportLayer transportLayer = appContext.getTransportLayer();
        try {
            transportLayer.initialize(transportId);
            final String result = toHex(transportLayer.sendCommand(GET_CHIPID));
            log.info("Health check response: {}", result);
            return StringUtils.isBlank(result)
                   ? ERROR.getCode()
                   : OK.getCode();
        } catch (Exception e) {
            log.error("Failed to perform health check using GET_CHIPID command: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return ERROR.getCode();
        } finally {
            transportLayer.disconnect();
        }
    }

    private static void logAttestationResult(VerifierExchangeResponseDTO attestationResult) {
        switch (VerifierExchangeResponse.from(attestationResult.getStatus())) {
            case OK -> log.info("*** ATTESTATION PASSED ***");
            case FAIL -> log.error("*** ATTESTATION FAILED ***");
            case ERROR -> log.error("*** ATTESTATION ERROR ***");
        }
    }
}
