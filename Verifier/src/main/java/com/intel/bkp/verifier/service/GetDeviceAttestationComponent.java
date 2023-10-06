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

import com.intel.bkp.command.exception.JtagUnknownCommandResponseException;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.protocol.spdm.exceptions.SpdmNotSupportedException;
import com.intel.bkp.protocol.spdm.exceptions.UnsupportedSpdmVersionException;
import com.intel.bkp.protocol.spdm.service.SpdmGetVersionMessageSender;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.protocol.sigma.service.GpDiceAttestationComponent;
import com.intel.bkp.verifier.protocol.sigma.service.GpGetCertificateMessageSender;
import com.intel.bkp.verifier.protocol.sigma.service.GpS10AttestationComponent;
import com.intel.bkp.verifier.protocol.sigma.service.TeardownMessageSender;
import com.intel.bkp.verifier.protocol.spdm.jna.SpdmProtocol12Impl;
import com.intel.bkp.verifier.protocol.spdm.service.SpdmDiceAttestationComponent;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.transport.model.TransportLayer;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static com.intel.bkp.command.model.CertificateRequestType.FIRMWARE;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class GetDeviceAttestationComponent {

    private final GpGetCertificateMessageSender gpGetCertificateMessageSender;
    private final GpS10AttestationComponent gpS10AttestationComponent;
    private final GpDiceAttestationComponent gpDiceAttestationComponent;
    private final SpdmGetVersionMessageSender spdmGetVersionMessageSender;
    private final TeardownMessageSender teardownMessageSender;
    private final SpdmDiceAttestationComponent spdmDiceAttestationComponent;

    public GetDeviceAttestationComponent() {
        this.gpGetCertificateMessageSender = new GpGetCertificateMessageSender();
        this.gpS10AttestationComponent = new GpS10AttestationComponent();
        this.gpDiceAttestationComponent = new GpDiceAttestationComponent();
        this.spdmGetVersionMessageSender = new SpdmGetVersionMessageSender(new SpdmProtocol12Impl());
        this.teardownMessageSender = new TeardownMessageSender();
        this.spdmDiceAttestationComponent = new SpdmDiceAttestationComponent();
    }

    public VerifierExchangeResponse perform(String refMeasurementHex, byte[] deviceId) {
        return perform(AppContext.instance(), refMeasurementHex, deviceId);
    }

    VerifierExchangeResponse perform(AppContext appContext, String refMeasurementHex, byte[] deviceId) {
        final TransportLayer transportLayer = appContext.getTransportLayer();
        final CommandLayer commandLayer = appContext.getCommandLayer();

        if (appContext.getLibConfig().isRunGpAttestation()) {
            log.debug("Forced GP ATTESTATION.");
            return runGpAttestation(refMeasurementHex, deviceId, transportLayer, commandLayer);
        } else if (!spdmSupported()) {
            return runGpAttestation(refMeasurementHex, deviceId, transportLayer, commandLayer);
        } else {
            return runSpdmAttestation(refMeasurementHex, deviceId);
        }
    }

    private boolean spdmSupported() {
        try {
            spdmGetVersionMessageSender.send();
            return true;
        } catch (UnsupportedSpdmVersionException | SpdmNotSupportedException e) {
            log.debug("SPDM not supported or insufficient version: ", e);
            return false;
        } catch (VerifierRuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new VerifierRuntimeException("Failed to verify if SPDM is supported.", e);
        }
    }

    private VerifierExchangeResponse runGpAttestation(String refMeasurementHex, byte[] deviceId,
                                                      TransportLayer transportLayer, CommandLayer commandLayer) {
        log.debug("Running GP Attestation.");
        teardownMessageSender.send(transportLayer, commandLayer);

        try {
            final byte[] response = gpGetCertificateMessageSender.send(transportLayer, commandLayer, FIRMWARE);
            log.debug("This board supports DICE certificate chain.");
            return gpDiceAttestationComponent.perform(response, refMeasurementHex, deviceId);
        } catch (JtagUnknownCommandResponseException e) {
            log.debug("This is S10 board: {}", e.getMessage());
            return gpS10AttestationComponent.perform(refMeasurementHex, deviceId);
        }
    }

    private VerifierExchangeResponse runSpdmAttestation(String refMeasurementHex, byte[] deviceId) {
        log.debug("Running SPDM Attestation.");
        return spdmDiceAttestationComponent.perform(refMeasurementHex, deviceId);
    }
}
