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

import com.intel.bkp.ext.core.endianess.EndianessActor;
import com.intel.bkp.verifier.Utils;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponse;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponseBuilder;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponseToTcbInfoMapper;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.model.dice.TcbInfo;
import com.intel.bkp.verifier.model.dice.TcbInfoAggregator;
import com.intel.bkp.verifier.model.dice.TcbInfoExtensionParser;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.List;

@ExtendWith(MockitoExtension.class)
public class EvidenceVerifierTestIT {

    private static final String TEST_FOLDER_INTEGRATION = "integration/";

    private static final String FILENAME_STRATIX_RIM = "signed_spl_hps.rim";
    private static final String FILENAME_AGILEX_RIM = "ghrd_sha_384.rim";

    private static final String FILENAME_STRATIX_RESPONSE = "measurements_response_stratix10.bin";
    private static final String FILENAME_AGILEX_RESPONSE = "measurements_response_agilex.bin";
    private static final String ALIAS_CERT = "alias_certificate.der";
    private static final String FIRMWARE_CERT = "firmware_certificate.der";
    private static final String DEVICE_ID_ENROLLMENT_CERT = "device_id_enrollment_certificate.der";

    private static String refMeasurementsStratix;
    private static String refMeasurementsAgilex;

    private static GetMeasurementResponse responseS10;
    private static GetMeasurementResponse responseAgilex;

    private static X509Certificate aliasCert;
    private static X509Certificate firmwareCert;
    private static X509Certificate deviceIdEnrollmentCert;

    private static final X509CertificateParser X509_PARSER = new X509CertificateParser();

    private final GetMeasurementResponseToTcbInfoMapper measurementMapper = new GetMeasurementResponseToTcbInfoMapper();
    private TcbInfoExtensionParser tcbInfoExtensionParser = new TcbInfoExtensionParser();
    private TcbInfoAggregator tcbInfoAggregator = new TcbInfoAggregator();

    private EvidenceVerifier sut = new EvidenceVerifier();

    @BeforeAll
    static void init() throws Exception {
        refMeasurementsStratix = readEvidence(FILENAME_STRATIX_RIM);
        refMeasurementsAgilex = readEvidence(FILENAME_AGILEX_RIM);

        responseS10 = readResponse(FILENAME_STRATIX_RESPONSE);
        responseAgilex = readResponse(FILENAME_AGILEX_RESPONSE);

        aliasCert = X509_PARSER.toX509(readCertificate(ALIAS_CERT));
        firmwareCert = X509_PARSER.toX509(readCertificate(FIRMWARE_CERT));
        deviceIdEnrollmentCert = X509_PARSER.toX509(readCertificate(DEVICE_ID_ENROLLMENT_CERT));
    }

    private static String readEvidence(String filename) throws Exception {
        return new String(Utils.readFromResources(TEST_FOLDER_INTEGRATION, filename));
    }

    private static GetMeasurementResponse readResponse(String filename) throws Exception {
        final byte[] response = Utils.readFromResources(TEST_FOLDER_INTEGRATION, filename);
        return new GetMeasurementResponseBuilder()
            .withActor(EndianessActor.FIRMWARE)
            .parse(response)
            .withActor(EndianessActor.SERVICE)
            .build();
    }

    private static byte[] readCertificate(String filename) throws Exception {
        return Utils.readFromResources(TEST_FOLDER_INTEGRATION, filename);
    }

    @Test
    public void verify_S10() {
        // given
        tcbInfoAggregator.add(measurementMapper.map(responseS10));

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoAggregator, refMeasurementsStratix);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.OK, result);
    }

    @Test
    public void verify_Agilex() {
        // given
        final List<TcbInfo> tcbInfosFromGetMeasurementResponse = measurementMapper.map(responseAgilex);

        tcbInfoExtensionParser.parse(aliasCert);
        tcbInfoExtensionParser.parse(firmwareCert);
        tcbInfoExtensionParser.parse(deviceIdEnrollmentCert);

        tcbInfoAggregator.add(tcbInfosFromGetMeasurementResponse);
        tcbInfoAggregator.add(tcbInfoExtensionParser.getTcbInfos());

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoAggregator, refMeasurementsAgilex);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.OK, result);
    }
}
