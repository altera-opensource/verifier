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

import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.protocol.common.model.evidence.IDeviceMeasurementsProvider;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.util.List;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@NoArgsConstructor
public class GpDiceAttestationComponent {

    private final IDeviceMeasurementsProvider<GpDeviceMeasurementsRequest> deviceMeasurementsProvider =
        new GpDeviceMeasurementsProvider();
    private EvidenceVerifier evidenceVerifier = new EvidenceVerifier();
    private TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator = new TcbInfoMeasurementsAggregator();
    private GpDiceChainService gpDiceChainService = new GpDiceChainService();

    public VerifierExchangeResponse perform(byte[] firmwareCertificateResponse, String refMeasurementHex,
                                            byte[] deviceId) {

        gpDiceChainService.fetchAndVerifyDiceChains(deviceId, firmwareCertificateResponse);

        tcbInfoMeasurementsAggregator.add(gpDiceChainService.getTcbInfoMeasurements());
        tcbInfoMeasurementsAggregator.add(getMeasurementsFromDevice(
            gpDiceChainService.getAliasPublicKey(), deviceId, PufType.EFUSE));

        return evidenceVerifier.verify(tcbInfoMeasurementsAggregator, refMeasurementHex);
    }

    private List<TcbInfoMeasurement> getMeasurementsFromDevice(PublicKey aliasKey, byte[] deviceId, PufType pufType) {
        final var measurementsRequest = GpDeviceMeasurementsRequest.forDice(deviceId, aliasKey, pufType);
        try {
            return deviceMeasurementsProvider.getMeasurementsFromDevice(measurementsRequest);
        } catch (Exception e) {
            throw new VerifierRuntimeException("Failed to retrieve measurements from device.", e);
        }
    }
}
