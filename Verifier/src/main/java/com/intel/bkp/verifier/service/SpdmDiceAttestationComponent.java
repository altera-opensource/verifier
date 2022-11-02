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
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoAggregator;
import com.intel.bkp.verifier.exceptions.SpdmCommandFailedException;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.interfaces.IDeviceMeasurementsProvider;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.service.certificate.SpdmDiceChainService;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import com.intel.bkp.verifier.service.measurements.SpdmDeviceMeasurementsProvider;
import com.intel.bkp.verifier.service.measurements.SpdmDeviceMeasurementsRequest;
import com.intel.bkp.verifier.service.sender.SpdmGetCertificateMessageSender;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.util.List;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class SpdmDiceAttestationComponent {

    private final IDeviceMeasurementsProvider<SpdmDeviceMeasurementsRequest> deviceMeasurementsProvider;
    private final EvidenceVerifier evidenceVerifier;
    private final TcbInfoAggregator tcbInfoAggregator;
    private final SpdmDiceChainService spdmDiceChainService;
    private final SpdmGetCertificateMessageSender spdmGetCertificateMessageSender;

    SpdmDiceAttestationComponent() {
        this.deviceMeasurementsProvider = new SpdmDeviceMeasurementsProvider();
        this.evidenceVerifier = new EvidenceVerifier();
        this.tcbInfoAggregator = new TcbInfoAggregator();
        this.spdmDiceChainService = new SpdmDiceChainService();
        this.spdmGetCertificateMessageSender = new SpdmGetCertificateMessageSender();
    }

    public VerifierExchangeResponse perform(String refMeasurement, byte[] deviceId) {
        getCertificateChain(deviceId);

        final List<TcbInfo> measurements = getMeasurementsFromDevice(spdmDiceChainService.getAliasPublicKey());

        tcbInfoAggregator.add(spdmDiceChainService.getTcbInfos());
        tcbInfoAggregator.add(measurements);

        return evidenceVerifier.verify(tcbInfoAggregator, refMeasurement);
    }

    private void getCertificateChain(byte[] deviceId) {
        try {
            final byte[] certificateChainFromDevice = spdmGetCertificateMessageSender.send();
            spdmDiceChainService.fetchAndVerifyDiceChains(deviceId, certificateChainFromDevice);
        } catch (SpdmCommandFailedException e) {
            log.error("GET_CERTIFICATE or GET_DIGEST failed - ignoring for now: ", e);
        } catch (Exception e) {
            throw new VerifierRuntimeException("Failed to verify DICE certificate chain.", e);
        }
    }

    private List<TcbInfo> getMeasurementsFromDevice(PublicKey aliasKey) {
        final var measurementsRequest = new SpdmDeviceMeasurementsRequest(aliasKey);
        try {
            return deviceMeasurementsProvider.getMeasurementsFromDevice(measurementsRequest);
        } catch (SpdmCommandFailedException e) {
            throw e;
        } catch (Exception e) {
            throw new VerifierRuntimeException("Failed to retrieve measurements from device.", e);
        }
    }
}
