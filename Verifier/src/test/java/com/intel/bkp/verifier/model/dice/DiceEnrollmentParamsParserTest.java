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

package com.intel.bkp.verifier.model.dice;

import com.intel.bkp.verifier.Utils;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

class DiceEnrollmentParamsParserTest {

    private static final String TEST_FOLDER = "responses/";
    private static final String DEVICE_ID_ENROLLMENT_CERT = "device_id_enrollment_certificate.der";
    private static final String EXPECTED_SKIER = "V97RVDQhiAUvGGca4JULu9ceUzo=";
    private static final String EXPECTED_SVN = "00";
    private static final X509CertificateParser X509_PARSER = new X509CertificateParser();

    private static X509Certificate deviceIdEnrollmentCert;

    private DiceEnrollmentParamsParser sut;

    @BeforeAll
    static void init() throws Exception {
        deviceIdEnrollmentCert = X509_PARSER.toX509(readCertificate(DEVICE_ID_ENROLLMENT_CERT));
    }

    @BeforeEach
    void setUp() {
        sut = new DiceEnrollmentParamsParser();
    }

    private static byte[] readCertificate(String filename) throws Exception {
        return Utils.readFromResources(TEST_FOLDER, filename);
    }

    @Test
    void parse() {
        // when
        sut.parse(deviceIdEnrollmentCert);

        // then
        Assertions.assertEquals(EXPECTED_SKIER, sut.getDiceEnrollmentParams().getSkiER());
        Assertions.assertEquals(EXPECTED_SVN, sut.getDiceEnrollmentParams().getSvn());
    }
}
