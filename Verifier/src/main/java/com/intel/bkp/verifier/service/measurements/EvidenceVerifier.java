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

import com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementHolder;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.utils.VerificationStatusLogger;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class EvidenceVerifier {

    private static final String EVIDENCE_VERIFICATION_MESSAGE = "Evidence verification";

    private final RimService rimService;

    public EvidenceVerifier() {
        this(new RimService());
    }

    public VerifierExchangeResponse verify(TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator,
                                           String refMeasurementHex) {
        log.debug("Received TcbInfos from device: {}", tcbInfoMeasurementsAggregator.mapToString());

        try {
            return Optional.of(refMeasurementHex)
                .filter(StringUtils::isNotBlank)
                .map(rimService::getMeasurements)
                    .map(holder -> {
                        addEndorsedMeasurementsToDeviceMeasurements(tcbInfoMeasurementsAggregator, holder);
                        return holder;
                    }).map(holder -> verifyReferenceWithDeviceMeasurements(tcbInfoMeasurementsAggregator, holder))
                .orElseGet(this::getResponseForEmptyRim);

        } catch (Exception e) {
            log.error("Exception occurred: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return VerifierExchangeResponse.ERROR;
        }
    }

    private VerifierExchangeResponse verifyReferenceWithDeviceMeasurements(
        TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator, MeasurementHolder measurementHolder) {
        return Optional.of(measurementHolder.getReferenceMeasurements())
            .filter(tcbInfoMeasurements -> !tcbInfoMeasurements.isEmpty())
            .map(tcbInfoMeasurements -> verifyInternal(tcbInfoMeasurements, tcbInfoMeasurementsAggregator))
            .orElseGet(this::getResponseForEmptyRim);
    }

    private void addEndorsedMeasurementsToDeviceMeasurements(TcbInfoMeasurementsAggregator tcbInfoAggregator,
                                                             MeasurementHolder measurementHolder) {
        tcbInfoAggregator.add(Optional.of(measurementHolder
            .getEndorsedMeasurements())
            .filter(tcbInfoMeasurements -> !tcbInfoMeasurements.isEmpty())
            .orElse(Collections.emptyList()));
    }

    private VerifierExchangeResponse verifyInternal(List<TcbInfoMeasurement> expectedTcbInfoMeasurements,
                                                    TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator) {

        log.info("*** VERIFYING EVIDENCE AGAINST RIM ***");

        final Map<TcbInfoKey, TcbInfoValue> tcbInfoResponseMap = tcbInfoMeasurementsAggregator.getMap();

        for (TcbInfoMeasurement measurement : expectedTcbInfoMeasurements) {
            log.info("Verification of measurement: {}", measurement.getKey());
            log.debug("Reference value: {}", measurement.getValue());

            if (!tcbInfoResponseMap.containsKey(measurement.getKey())) {
                log.error(VerificationStatusLogger.failure(EVIDENCE_VERIFICATION_MESSAGE));
                log.error("Response does not contain expected key.");
                return VerifierExchangeResponse.FAIL;
            }

            final TcbInfoValue responseValue = tcbInfoResponseMap.get(measurement.getKey());
            log.debug("Received value: {}", responseValue);

            if (!responseValue.matchesReferenceValue(measurement.getValue())) {
                log.error("""
                    Evidence verification failed.
                    Reference: {}
                    Actual:    {}
                    """, measurement.getValue(), responseValue);
                return VerifierExchangeResponse.FAIL;
            }

            log.info(VerificationStatusLogger.success(EVIDENCE_VERIFICATION_MESSAGE));
        }

        return VerifierExchangeResponse.OK;
    }

    private VerifierExchangeResponse getResponseForEmptyRim() {
        log.warn("List of expected measurements in RIM is empty.");
        return VerifierExchangeResponse.OK;
    }
}
