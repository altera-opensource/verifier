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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.intel.bkp.command.responses.spdm.SpdmMeasurementResponse;
import com.intel.bkp.command.responses.spdm.SpdmMeasurementResponseBuilder;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.protocol.spdm.service.SpdmMeasurementResponseProvider;
import com.intel.bkp.verifier.protocol.spdm.service.SpdmMeasurementResponseToTcbInfoMapper;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static com.intel.bkp.test.FileUtils.readFromResources;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
public class EvidenceVerifierSpdmTestIT {

    private static final int MAX_FUZZ_STR_LEN = 1000;
    private static final String TEST_FOLDER_INTEGRATION = "integration/spdm/";

    private static final String FILENAME_AGILEX_RIM = "hps_fpga_signed_enc_test.rim";

    private static final String FILENAME_AGILEX_RIM_WITH_PR_REGION = "ghrd_agfd023r25a2e2vr0_pr.rim";

    private static final String FILENAME_AGILEX_RIM_FUZZ = "hps_fpga_signed_enc_test_fuzz.rim";

    private static final String FILENAME_AGILEX_RESPONSE = "measurements_hps_fpga_signed_enc_test.bin";

    private static final String FILENAME_AGILEX_RESPONSE_WITH_PR_REGION = "measurements_ghrd_agfd023r25a2e2vr0_pr.bin";

    private static String refMeasurementsAgilex;
    private static String refMeasurementsAgilexWithPrRegion;
    private static String refMeasurementsAgilexFuzz;
    private static SpdmMeasurementResponseProvider responseAgilex;
    private static SpdmMeasurementResponseProvider responseAgilexWithPrRegion;

    private final SpdmMeasurementResponseToTcbInfoMapper measurementMapper =
        new SpdmMeasurementResponseToTcbInfoMapper();
    private final TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator = new TcbInfoMeasurementsAggregator();

    private EvidenceVerifier sut = new EvidenceVerifier();

    @BeforeAll
    static void init() throws Exception {
        refMeasurementsAgilex = readEvidence(FILENAME_AGILEX_RIM);
        refMeasurementsAgilexWithPrRegion = readEvidence(FILENAME_AGILEX_RIM_WITH_PR_REGION);
        refMeasurementsAgilexFuzz = readEvidence(FILENAME_AGILEX_RIM_FUZZ);

        responseAgilex =
            new SpdmMeasurementResponseProvider(readResponse(FILENAME_AGILEX_RESPONSE));
        responseAgilexWithPrRegion =
            new SpdmMeasurementResponseProvider(readResponse(FILENAME_AGILEX_RESPONSE_WITH_PR_REGION));
    }

    private static String readEvidence(String filename) throws Exception {
        return toHex(readFromResources(TEST_FOLDER_INTEGRATION, filename));
    }

    private static SpdmMeasurementResponse readResponse(String filename) throws Exception {
        final byte[] response = readFromResources(TEST_FOLDER_INTEGRATION, filename);
        return new SpdmMeasurementResponseBuilder()
            .parse(response)
            .build();
    }

    private static String getFuzzHex(FuzzedDataProvider data) {
        return toHex(data.consumeBytes(MAX_FUZZ_STR_LEN / 2));
    }

    private static void fuzzRandomTcbInfoMeasurement(FuzzedDataProvider data,
                                                     List<TcbInfoMeasurement> tcbInfosFromDevice) {
        final int elemToChange = data.consumeInt(0, tcbInfosFromDevice.size() - 1);
        System.out.println("Elem to change: " + elemToChange);

        final TcbInfoValue tcbInfoValue = tcbInfosFromDevice.get(elemToChange).getValue();
        System.out.println("Current tcbInfoValue: " + tcbInfoValue);

        tcbInfoValue.getFwid().ifPresent(fwIdField -> {
            final String newFieldValue = fuzzFieldValue(data, fwIdField.getDigest());
            fwIdField.setDigest(newFieldValue);
        });

        tcbInfoValue.getMaskedVendorInfo().ifPresent(maskedVendorInfo -> {
            final String newVendorInfo = fuzzFieldValue(data, maskedVendorInfo.getVendorInfo());
            maskedVendorInfo.setVendorInfo(newVendorInfo);
        });

        System.out.println("Updated tcbInfoValue: " + tcbInfoValue);
    }

    private static String fuzzFieldValue(FuzzedDataProvider data, String currentFieldValue) {
        String newFieldValue;
        do {
            newFieldValue = getFuzzHex(data);
        } while (currentFieldValue.equals(newFieldValue));
        return newFieldValue;
    }

    @Tag("Fuzz")
    @FuzzTest
    public void verify_Spdm_Agilex_Fuzz(FuzzedDataProvider data) {
        // given
        final var tcbInfoMeasurementsAggregator = new TcbInfoMeasurementsAggregator();
        final List<TcbInfoMeasurement> tcbInfosFromDevice = measurementMapper.map(responseAgilex);

        fuzzRandomTcbInfoMeasurement(data, tcbInfosFromDevice);
        tcbInfoMeasurementsAggregator.add(tcbInfosFromDevice);

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoMeasurementsAggregator, refMeasurementsAgilexFuzz);

        // then
        assertEquals(VerifierExchangeResponse.FAIL, result);
    }

    @Test
    public void verify_Spdm_Agilex() {
        // given
        tcbInfoMeasurementsAggregator.add(measurementMapper.map(responseAgilex));

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoMeasurementsAggregator, refMeasurementsAgilex);

        // then
        assertEquals(VerifierExchangeResponse.OK, result);
    }

    @Test
    public void verify_Spdm_AgilexWithPrRegion() {
        // given
        tcbInfoMeasurementsAggregator.add(measurementMapper.map(responseAgilexWithPrRegion));

        // when
        final VerifierExchangeResponse result =
            sut.verify(tcbInfoMeasurementsAggregator, refMeasurementsAgilexWithPrRegion);

        // then
        assertEquals(VerifierExchangeResponse.OK, result);
    }
}
