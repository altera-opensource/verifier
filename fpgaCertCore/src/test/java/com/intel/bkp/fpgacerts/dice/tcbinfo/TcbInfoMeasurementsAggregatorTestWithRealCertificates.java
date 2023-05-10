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

package com.intel.bkp.fpgacerts.dice.tcbinfo;

import com.intel.bkp.fpgacerts.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Map;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement.asMeasurements;

@ExtendWith(MockitoExtension.class)
class TcbInfoMeasurementsAggregatorTestWithRealCertificates {

    private static final String TEST_FOLDER = "certs/dice/";

    // These certificates were parsed manually in ASN.1 Editor
    private static final String ALIAS_CERT = "alias_certificate.der";
    private static final String FIRMWARE_CERT = "firmware_certificate.der";
    private static final String DEVICE_ID_ENROLLMENT_CERT = "device_id_enrollment_certificate.der";

    private static X509Certificate aliasCert;
    private static X509Certificate firmwareCert;
    private static X509Certificate deviceIdEnrollmentCert;

    private final TcbInfoExtensionParser tcbInfoExtensionParser = new TcbInfoExtensionParser();

    private TcbInfoMeasurementsAggregator sut;

    @BeforeAll
    static void init() throws Exception {
        aliasCert = Utils.readCertificate(TEST_FOLDER, ALIAS_CERT);
        firmwareCert = Utils.readCertificate(TEST_FOLDER, FIRMWARE_CERT);
        deviceIdEnrollmentCert = Utils.readCertificate(TEST_FOLDER, DEVICE_ID_ENROLLMENT_CERT);
    }

    @BeforeEach
    void setUp() {
        sut = new TcbInfoMeasurementsAggregator();
    }

    @Test
    void add_IsAddedProperly() {
        // given
        final var tcbInfos = new ArrayList<TcbInfo>();
        tcbInfos.addAll(tcbInfoExtensionParser.parse(aliasCert));
        tcbInfos.addAll(tcbInfoExtensionParser.parse(firmwareCert));
        tcbInfos.addAll(tcbInfoExtensionParser.parse(deviceIdEnrollmentCert));
        final var measurements = asMeasurements(tcbInfos);

        // when
        sut.add(measurements);

        // then
        final Map<TcbInfoKey, TcbInfoValue> result = sut.getMap();
        Assertions.assertEquals(4, result.size());
    }
}
