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

import com.intel.bkp.verifier.exceptions.UnknownCommandException;
import com.intel.bkp.verifier.interfaces.CommandLayer;
import com.intel.bkp.verifier.interfaces.TransportLayer;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.sender.GetCertificateMessageSender;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static com.intel.bkp.verifier.model.CertificateRequestType.FIRMWARE;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class GetDeviceAttestationComponent {

    private final GetCertificateMessageSender getCertificateMessageSender;
    private final S10AttestationComponent s10AttestationComponent;
    private final DiceAttestationComponent diceAttestationComponent;

    public GetDeviceAttestationComponent() {
        this(new GetCertificateMessageSender(), new S10AttestationComponent(), new DiceAttestationComponent());
    }

    public VerifierExchangeResponse perform(String refMeasurement, byte[] deviceId) {
        return perform(AppContext.instance(), refMeasurement, deviceId);
    }

    VerifierExchangeResponse perform(AppContext appContext, String refMeasurement, byte[] deviceId) {

        final TransportLayer transportLayer = appContext.getTransportLayer();
        final CommandLayer commandLayer = appContext.getCommandLayer();
        try {
            final byte[] response = getCertificateMessageSender.send(transportLayer, commandLayer, FIRMWARE);
            log.debug("This is FM/DM board.");
            return diceAttestationComponent.perform(response, refMeasurement, deviceId);
        } catch (UnknownCommandException e) {
            log.debug("This is S10 board: {}", e.getMessage());
            return s10AttestationComponent.perform(refMeasurement, deviceId);
        }
    }
}
