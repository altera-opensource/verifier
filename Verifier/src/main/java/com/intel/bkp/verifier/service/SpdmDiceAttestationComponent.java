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

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.interfaces.IDeviceMeasurementsProvider;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.certificate.DiceChainMeasurementsCollector;
import com.intel.bkp.verifier.service.certificate.SpdmCertificateChainHolder;
import com.intel.bkp.verifier.service.certificate.SpdmChainSearcher;
import com.intel.bkp.verifier.service.certificate.SpdmValidChains;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import com.intel.bkp.verifier.service.measurements.SpdmDeviceMeasurementsProvider;
import com.intel.bkp.verifier.service.measurements.SpdmDeviceMeasurementsRequest;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import static com.intel.bkp.verifier.jna.model.SpdmConstants.DEFAULT_SLOT_ID;
import static com.intel.bkp.verifier.service.certificate.DiceChainType.ATTESTATION;
import static com.intel.bkp.verifier.service.certificate.DiceChainType.IID;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class SpdmDiceAttestationComponent {

    private final IDeviceMeasurementsProvider<SpdmDeviceMeasurementsRequest> deviceMeasurementsProvider;
    private final EvidenceVerifier evidenceVerifier;
    private final Supplier<TcbInfoMeasurementsAggregator> tcbInfoMeasurementsAggregator;
    private final DiceChainMeasurementsCollector measurementsCollector;
    private final SpdmChainSearcher spdmChainSearcher;

    SpdmDiceAttestationComponent() {
        this.deviceMeasurementsProvider = new SpdmDeviceMeasurementsProvider();
        this.evidenceVerifier = new EvidenceVerifier();
        this.tcbInfoMeasurementsAggregator = TcbInfoMeasurementsAggregator::new;
        this.measurementsCollector = new DiceChainMeasurementsCollector();
        this.spdmChainSearcher = new SpdmChainSearcher();
    }

    public VerifierExchangeResponse perform(String refMeasurement, byte[] deviceId) {
        final TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator = this.tcbInfoMeasurementsAggregator.get();

        if (withMeasurementsSignatureVerification()) {
            final SpdmValidChains validChains = spdmChainSearcher.searchValidChains(deviceId);

            final var measurementsFromCertChain = getMeasurementsFromChain(validChains.get(ATTESTATION));
            final var iidUdsChainMeasurements = getMeasurementsFromChain(validChains.get(IID));
            final var measurementsFromDevice = getMeasurementsFromDevice(getSlotId(validChains));

            log.info("*** COLLECTING EVIDENCE FROM CERTIFICATES AND DEVICE ***");
            tcbInfoMeasurementsAggregator.add(measurementsFromCertChain);
            tcbInfoMeasurementsAggregator.add(iidUdsChainMeasurements);
            tcbInfoMeasurementsAggregator.add(measurementsFromDevice);
        } else {
            log.warn("Chain verification and measurements signature verification turned off!");

            log.info("*** COLLECTING EVIDENCE FROM DEVICE ***");
            tcbInfoMeasurementsAggregator.add(getMeasurementsFromDevice());
        }

        return evidenceVerifier.verify(tcbInfoMeasurementsAggregator, refMeasurement);
    }

    private boolean withMeasurementsSignatureVerification() {
        return AppContext.instance().getLibConfig().getLibSpdmParams().isMeasurementsRequestSignature();
    }

    private Integer getSlotId(SpdmValidChains validChains) {
        return Optional.ofNullable(validChains.get(ATTESTATION))
            .map(SpdmCertificateChainHolder::slotId)
            .orElseThrow(() -> new VerifierRuntimeException("Valid attestation chain not found."));
    }

    private List<TcbInfoMeasurement> getMeasurementsFromChain(SpdmCertificateChainHolder chainHolder) {
        return Optional.ofNullable(chainHolder)
            .map(SpdmCertificateChainHolder::chain)
            .map(measurementsCollector::getMeasurementsFromCertChain)
            .orElse(List.of());
    }

    private List<TcbInfoMeasurement> getMeasurementsFromDevice() {
        return getMeasurementsFromDevice(DEFAULT_SLOT_ID);
    }

    private List<TcbInfoMeasurement> getMeasurementsFromDevice(int slotId) {
        final var measurementsRequest = new SpdmDeviceMeasurementsRequest(slotId);
        try {
            return deviceMeasurementsProvider.getMeasurementsFromDevice(measurementsRequest);
        } catch (Exception e) {
            throw new VerifierRuntimeException("Failed to retrieve measurements from device.", e);
        }
    }
}
