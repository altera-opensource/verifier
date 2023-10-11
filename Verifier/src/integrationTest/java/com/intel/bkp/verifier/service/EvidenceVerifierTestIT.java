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

import com.intel.bkp.command.responses.sigma.GetMeasurementResponse;
import com.intel.bkp.command.responses.sigma.GetMeasurementResponseBuilder;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoExtensionParser;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.protocol.sigma.model.evidence.GetMeasurementResponseProvider;
import com.intel.bkp.verifier.protocol.sigma.service.GpMeasurementResponseToTcbInfoMapper;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.List;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement.asMeasurements;
import static com.intel.bkp.fpgacerts.utils.X509UtilsWrapper.toX509;
import static com.intel.bkp.test.FileUtils.readFromResources;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
public class EvidenceVerifierTestIT {

    private static final String TEST_FOLDER_INTEGRATION = "integration/";
    private static final String FILENAME_STRATIX_RIM = "signed_spl_hps.rim";
    private static final String FILENAME_STRATIX_RIM_INVALID_IO_SECTION = "signed_spl_hps_invalid_io_section.rim";
    private static final String FILENAME_AGILEX_RIM = "ghrd_sha_384.rim";
    private static final String FILENAME_AGILEX_RIM_INVALID_HPS_SECTION = "ghrd_sha_384_invalid_hps_section.rim";
    private static final String FILENAME_STRATIX_RESPONSE = "measurements_response_stratix10.bin";
    private static final String FILENAME_AGILEX_RESPONSE = "measurements_response_agilex.bin";
    private static final String ALIAS_CERT = "alias_certificate.der";
    private static final String FIRMWARE_CERT = "firmware_certificate.der";
    private static final String DEVICE_ID_ENROLLMENT_CERT = "device_id_enrollment_certificate.der";

    private static String refMeasurementsStratix;
    private static String refMeasurementsStratixInvalidIoSection;
    private static String refMeasurementsAgilex;
    private static String refMeasurementsAgilexInvalidHpsSection;

    private static GetMeasurementResponseProvider responseS10;
    private static GetMeasurementResponseProvider responseAgilex;

    private static X509Certificate aliasCert;
    private static X509Certificate firmwareCert;
    private static X509Certificate deviceIdEnrollmentCert;

    private final GpMeasurementResponseToTcbInfoMapper measurementMapper = new GpMeasurementResponseToTcbInfoMapper();
    private final TcbInfoExtensionParser tcbInfoExtensionParser = new TcbInfoExtensionParser();
    private final TcbInfoMeasurementsAggregator tcbInfoAggregator = new TcbInfoMeasurementsAggregator();

    private final EvidenceVerifier sut = new EvidenceVerifier();

    @BeforeAll
    static void init() throws Exception {
        refMeasurementsStratix = readEvidence(FILENAME_STRATIX_RIM);
        refMeasurementsStratixInvalidIoSection = readEvidence(FILENAME_STRATIX_RIM_INVALID_IO_SECTION);
        refMeasurementsAgilex = readEvidence(FILENAME_AGILEX_RIM);
        refMeasurementsAgilexInvalidHpsSection = readEvidence(FILENAME_AGILEX_RIM_INVALID_HPS_SECTION);

        responseS10 = new GetMeasurementResponseProvider(readResponse(FILENAME_STRATIX_RESPONSE));
        responseAgilex = new GetMeasurementResponseProvider(readResponse(FILENAME_AGILEX_RESPONSE));

        aliasCert = toX509(readCertificate(ALIAS_CERT));
        firmwareCert = toX509(readCertificate(FIRMWARE_CERT));
        deviceIdEnrollmentCert = toX509(readCertificate(DEVICE_ID_ENROLLMENT_CERT));
    }

    private static String readEvidence(String filename) throws Exception {
        return toHex(readFromResources(TEST_FOLDER_INTEGRATION, filename));
    }

    private static GetMeasurementResponse readResponse(String filename) throws Exception {
        final byte[] response = readFromResources(TEST_FOLDER_INTEGRATION, filename);
        return new GetMeasurementResponseBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(response)
            .withActor(EndiannessActor.SERVICE)
            .build();
    }

    @SneakyThrows
    private static byte[] readCertificate(String filename) {
        return readFromResources(TEST_FOLDER_INTEGRATION, filename);
    }

    @Test
    public void verify_S10() {
        // given
        prepareTcbInfoAggregatorForS10();

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoAggregator, refMeasurementsStratix);

        // then
        assertEquals(VerifierExchangeResponse.OK, result);
    }

    @Test
    public void verify_S10_InvalidIoMeasurements_ReturnsFail() {
        // given
        prepareTcbInfoAggregatorForS10();

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoAggregator, refMeasurementsStratixInvalidIoSection);

        // then
        assertEquals(VerifierExchangeResponse.FAIL, result);
    }

    @Test
    public void verify_Agilex() {
        // given
        prepareTcbInfoMeasurementsAggregatorForAgilex();

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoAggregator, refMeasurementsAgilex);

        // then
        assertEquals(VerifierExchangeResponse.OK, result);
    }

    @Test
    public void verify_Agilex_InvalidHpsMeasurements_ReturnsFail() {
        // given
        prepareTcbInfoMeasurementsAggregatorForAgilex();

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoAggregator, refMeasurementsAgilexInvalidHpsSection);

        // then
        assertEquals(VerifierExchangeResponse.FAIL, result);
    }

    private void prepareTcbInfoAggregatorForS10() {
        tcbInfoAggregator.add(measurementMapper.map(responseS10));
    }

    private void prepareTcbInfoMeasurementsAggregatorForAgilex() {
        final List<TcbInfoMeasurement> tcbInfosFromGetMeasurementResponse = measurementMapper.map(responseAgilex);
        tcbInfoAggregator.add(tcbInfosFromGetMeasurementResponse);

        tcbInfoAggregator.add(getMeasurementsFromCertificate(aliasCert));
        tcbInfoAggregator.add(getMeasurementsFromCertificate(firmwareCert));
        tcbInfoAggregator.add(getMeasurementsFromCertificate(deviceIdEnrollmentCert));
    }

    private List<TcbInfoMeasurement> getMeasurementsFromCertificate(X509Certificate aliasCert) {
        return asMeasurements(tcbInfoExtensionParser.parse(aliasCert));
    }
}
