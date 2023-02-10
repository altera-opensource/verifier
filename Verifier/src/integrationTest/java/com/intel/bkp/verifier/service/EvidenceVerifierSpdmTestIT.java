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

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import com.intel.bkp.verifier.Utils;
import com.intel.bkp.verifier.command.responses.attestation.SpdmMeasurementResponse;
import com.intel.bkp.verifier.command.responses.attestation.SpdmMeasurementResponseBuilder;
import com.intel.bkp.verifier.command.responses.attestation.SpdmMeasurementResponseToTcbInfoMapper;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class EvidenceVerifierSpdmTestIT {

    private static final String TEST_FOLDER_INTEGRATION = "integration/spdm/";

    private static final String FILENAME_AGILEX_RIM = "hps_fpga_signed_enc_test.rim";

    private static final String FILENAME_AGILEX_RIM_WITH_PR_REGION = "ghrd_agfd023r25a2e2vr0_pr.rim";

    private static final String FILENAME_AGILEX_RESPONSE = "measurements_hps_fpga_signed_enc_test.bin";

    private static final String FILENAME_AGILEX_RESPONSE_WITH_PR_REGION = "measurements_ghrd_agfd023r25a2e2vr0_pr.bin";

    private static String refMeasurementsAgilex;
    private static String refMeasurementsAgilexWithPrRegion;
    private static SpdmMeasurementResponse responseAgilex;
    private static SpdmMeasurementResponse responseAgilexWithPrRegion;

    private final SpdmMeasurementResponseToTcbInfoMapper measurementMapper =
        new SpdmMeasurementResponseToTcbInfoMapper();
    private TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator = new TcbInfoMeasurementsAggregator();

    private EvidenceVerifier sut = new EvidenceVerifier();

    @BeforeAll
    static void init() throws Exception {
        refMeasurementsAgilex = readEvidence(FILENAME_AGILEX_RIM);
        responseAgilex = readResponse(FILENAME_AGILEX_RESPONSE);
        refMeasurementsAgilexWithPrRegion = readEvidence(FILENAME_AGILEX_RIM_WITH_PR_REGION);
        responseAgilexWithPrRegion = readResponse(FILENAME_AGILEX_RESPONSE_WITH_PR_REGION);
    }

    private static String readEvidence(String filename) throws Exception {
        return new String(Utils.readFromResources(TEST_FOLDER_INTEGRATION, filename));
    }

    private static SpdmMeasurementResponse readResponse(String filename) throws Exception {
        final byte[] response = Utils.readFromResources(TEST_FOLDER_INTEGRATION, filename);
        return new SpdmMeasurementResponseBuilder()
            .parse(response)
            .build();
    }

    @Test
    public void verify_Spdm_Agilex() {
        // given
        tcbInfoMeasurementsAggregator.add(measurementMapper.map(responseAgilex));

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoMeasurementsAggregator, refMeasurementsAgilex);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.OK, result);
    }

    @Test
    public void verify_Spdm_AgilexWithPrRegion() {
        // given
        tcbInfoMeasurementsAggregator.add(measurementMapper.map(responseAgilexWithPrRegion));

        // when
        final VerifierExchangeResponse result =
            sut.verify(tcbInfoMeasurementsAggregator, refMeasurementsAgilexWithPrRegion);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.OK, result);
    }
}
