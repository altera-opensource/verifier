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

package com.intel.bkp.fpgacerts.dice.tcbinfo;

import com.intel.bkp.fpgacerts.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoConstants.FWIDS_HASH_ALG;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoConstants.VENDOR;
import static com.intel.bkp.fpgacerts.model.Oid.MEASUREMENT_TYPES;

class TcbInfoExtensionParserTest {

    private static final String TEST_FOLDER = "certs/dice/";

    // These certificates were parsed manually in ASN.1 Editor
    private static final String ALIAS_CERT = "alias_certificate.der";
    private static final String FIRMWARE_CERT = "firmware_certificate.der";
    private static final String DEVICE_ID_ENROLLMENT_CERT = "device_id_enrollment_certificate.der";

    private static final String EXPECTED_VENDOR = VENDOR;
    private static final String EXPECTED_MODEL = "Agilex";
    private static final String EXPECTED_HASH_ALG = FWIDS_HASH_ALG;

    private static final int ALIAS_EXPECTED_LAYER = 2;
    private static final String ALIAS_EXPECTED_DIGEST_1 = "066331A2C0CD05F2F48D5BDD4EA60C5CFFAE61C286B1ADDE040E1"
        + "F821EC8199FF76AA3750C8DE1382CDB14B067A8E0E3";
    private static final String ALIAS_EXPECTED_DIGEST_2 = "FEC20013FCD2D2187176FED7DB8537B93695C845B76F98658FCC8"
        + "350EE5341FC196D8CBCE4DDA1098B075AE67F148D73";
    private static final String ALIAS_EXPECTED_TYPE_1 = MEASUREMENT_TYPES.getOid() + ".2";
    private static final String ALIAS_EXPECTED_TYPE_2 = MEASUREMENT_TYPES.getOid() + ".3";

    private static final int FIRMWARE_EXPECTED_SVN = 1;
    private static final int FIRMWARE_EXPECTED_LAYER = 1;
    private static final int FIRMWARE_EXPECTED_INDEX = 0;
    private static final String FIRMWARE_EXPECTED_DIGEST = "9430BBFC85A933E15A87E04D12A86D4231A88DC7FE58F388ED0C"
        + "B3235EF3E7D5BB1CC91C72C4BA7A045971AE07B91F61";
    private static final String FIRMWARE_EXPECTED_FLAGS = "40";

    private static final int DEVICEID_EXPECTED_SVN = 0;
    private static final int DEVICEID_EXPECTED_LAYER = 0;
    private static final int DEVICEID_EXPECTED_INDEX = 0;
    private static final String DEVICEID_EXPECTED_DIGEST = "B0C5586D865C5C71F203CF905D0160A15407276D7CAF65AE2D29"
        + "9F486E207D0AA8BE820309281C6CA6CE99319204C4F2";

    private static X509Certificate aliasCert;
    private static X509Certificate firmwareCert;
    private static X509Certificate deviceIdEnrollmentCert;

    private TcbInfoExtensionParser sut;

    @BeforeAll
    static void init() throws Exception {
        aliasCert = Utils.readCertificate(TEST_FOLDER, ALIAS_CERT);
        firmwareCert = Utils.readCertificate(TEST_FOLDER, FIRMWARE_CERT);
        deviceIdEnrollmentCert = Utils.readCertificate(TEST_FOLDER, DEVICE_ID_ENROLLMENT_CERT);
    }

    @BeforeEach
    void setUp() {
        sut = new TcbInfoExtensionParser();
    }

    @Test
    void parse_WithAliasCert() {
        // when
        final List<TcbInfo> tcbInfos = sut.parse(aliasCert);

        // then
        Assertions.assertEquals(2, tcbInfos.size());

        final TcbInfo tcbInfo = tcbInfos.get(0);
        Assertions.assertEquals(EXPECTED_VENDOR, tcbInfo.get(TcbInfoField.VENDOR).get());
        Assertions.assertEquals(ALIAS_EXPECTED_LAYER, tcbInfo.get(TcbInfoField.LAYER).get());
        Assertions.assertEquals(ALIAS_EXPECTED_TYPE_1, tcbInfo.get(TcbInfoField.TYPE).get());
        assertFwId(tcbInfo, ALIAS_EXPECTED_DIGEST_1);

        final TcbInfo tcbInfo2 = tcbInfos.get(1);
        Assertions.assertEquals(EXPECTED_VENDOR, tcbInfo2.get(TcbInfoField.VENDOR).get());
        Assertions.assertEquals(ALIAS_EXPECTED_LAYER, tcbInfo2.get(TcbInfoField.LAYER).get());
        Assertions.assertEquals(ALIAS_EXPECTED_TYPE_2, tcbInfo2.get(TcbInfoField.TYPE).get());
        assertFwId(tcbInfo2, ALIAS_EXPECTED_DIGEST_2);
    }

    @Test
    void parse_WithFirmwareCert() {
        // when
        final List<TcbInfo> tcbInfos = sut.parse(firmwareCert);

        // then
        Assertions.assertEquals(1, tcbInfos.size());

        final TcbInfo tcbInfo = tcbInfos.get(0);
        Assertions.assertEquals(EXPECTED_VENDOR, tcbInfo.get(TcbInfoField.VENDOR).get());
        Assertions.assertEquals(EXPECTED_MODEL, tcbInfo.get(TcbInfoField.MODEL).get());
        Assertions.assertEquals(FIRMWARE_EXPECTED_SVN, tcbInfo.get(TcbInfoField.SVN).get());
        Assertions.assertEquals(FIRMWARE_EXPECTED_LAYER, tcbInfo.get(TcbInfoField.LAYER).get());
        Assertions.assertEquals(FIRMWARE_EXPECTED_INDEX, tcbInfo.get(TcbInfoField.INDEX).get());
        Assertions.assertEquals(FIRMWARE_EXPECTED_FLAGS, tcbInfo.get(TcbInfoField.FLAGS).get());
        assertFwId(tcbInfo, FIRMWARE_EXPECTED_DIGEST);
    }

    @Test
    void parse_WithDeviceIdEnrollmentCert() {
        // when
        final List<TcbInfo> tcbInfos = sut.parse(deviceIdEnrollmentCert);

        // then
        Assertions.assertEquals(1, tcbInfos.size());

        final TcbInfo tcbInfo = tcbInfos.get(0);
        Assertions.assertEquals(EXPECTED_VENDOR, tcbInfo.get(TcbInfoField.VENDOR).get());
        Assertions.assertEquals(EXPECTED_MODEL, tcbInfo.get(TcbInfoField.MODEL).get());
        Assertions.assertEquals(DEVICEID_EXPECTED_SVN, tcbInfo.get(TcbInfoField.SVN).get());
        Assertions.assertEquals(DEVICEID_EXPECTED_LAYER, tcbInfo.get(TcbInfoField.LAYER).get());
        Assertions.assertEquals(DEVICEID_EXPECTED_INDEX, tcbInfo.get(TcbInfoField.INDEX).get());
        assertFwId(tcbInfo, DEVICEID_EXPECTED_DIGEST);
    }

    private void assertFwId(TcbInfo tcbInfo, String expectedDigest) {
        final FwIdField fwId = (FwIdField) tcbInfo.get(TcbInfoField.FWIDS)
            .orElseThrow(() -> new RuntimeException("Expected FwId field in TcbInfo, but it does not exist."));
        Assertions.assertEquals(EXPECTED_HASH_ALG, fwId.getHashAlg());
        Assertions.assertEquals(expectedDigest, fwId.getDigest());
    }
}
