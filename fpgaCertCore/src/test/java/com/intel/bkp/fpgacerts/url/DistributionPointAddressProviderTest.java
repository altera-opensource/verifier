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

package com.intel.bkp.fpgacerts.url;

import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.fpgacerts.model.SmartNicFamily;
import com.intel.bkp.fpgacerts.model.UdsChoice;
import com.intel.bkp.fpgacerts.url.params.DiceEnrollmentParams;
import com.intel.bkp.fpgacerts.url.params.DiceParams;
import com.intel.bkp.fpgacerts.url.params.NicDiceParams;
import com.intel.bkp.fpgacerts.url.params.RimParams;
import com.intel.bkp.fpgacerts.url.params.RimSignedDataParams;
import com.intel.bkp.fpgacerts.url.params.S10Params;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DistributionPointAddressProviderTest {

    private static final String PATH_CER_WITH_SLASH = "https://tsci.intel.com/content/IPCS/certs/";
    private static final String PATH_CER_WITHOUT_SLASH = "https://tsci.intel.com/content/IPCS/certs";
    private static final String PATH_NIC_CER_WITH_SLASH = "https://tsci.intel.com/content/NIC/certs/";
    private static final String PATH_NIC_CER_WITHOUT_SLASH = "https://tsci.intel.com/content/NIC/certs";

    private static final String PATH_RIM_WITH_SLASH = "https://tsci.intel.com/content/IPCS/rims/";
    private static final String PATH_XRIM_WITH_SLASH = "https://tsci.intel.com/content/IPCS/crls/";

    private static final S10Params S10_PARAMS = new S10Params("deviceId", "pufType");
    private static final DiceParams DICE_PARAMS = new DiceParams("skiInBase64", "UID");
    private static final DiceEnrollmentParams DICE_ENROLLMENT_PARAMS =
        new DiceEnrollmentParams("skiERinBase64", "SVN", "UID");

    private static final NicDiceParams NIC_PARAMS_FOR_MEV = new NicDiceParams("skiInBase64", "UID", SmartNicFamily.MEV);
    private static final NicDiceParams NIC_PARAMS_FOR_LKV = new NicDiceParams("skiInBase64", "UID", SmartNicFamily.LKV);
    private static final NicDiceParams NIC_PARAMS_FOR_CNV = new NicDiceParams("skiInBase64", "UID", SmartNicFamily.CNV);
    private static final String EXPECTED_ATTESTATION_PATH = PATH_CER_WITH_SLASH + "attestation_DEVICEID_PUFTYPE.cer";
    private static final String EXPECTED_DEVICE_ID_PATH = PATH_CER_WITH_SLASH + "deviceid_uid_skiInBase64.cer";
    private static final String EXPECTED_ENROLLMENT_PATH = PATH_CER_WITH_SLASH + "enrollment_uid_svn_skiERinBase64.cer";
    private static final String EXPECTED_IID_UDS_PATH = PATH_CER_WITH_SLASH + "iiduds_uid_skiInBase64.cer";
    private static final String EXPECTED_NIC_MEV_PATH = PATH_NIC_CER_WITH_SLASH + "01_uid.cer";
    private static final String EXPECTED_NIC_LKV_PATH = PATH_NIC_CER_WITH_SLASH + "02_uid_skiInBase64.cer";
    private static final String EXPECTED_NIC_CNV_PATH = PATH_NIC_CER_WITH_SLASH + "03_uid_skiInBase64.cer";

    private static final DistributionPointAddressProvider SUT =
        new DistributionPointAddressProvider(PATH_CER_WITH_SLASH, PATH_NIC_CER_WITH_SLASH);
    private static final DistributionPointAddressProvider SUT_WITHOUT_SLASH =
        new DistributionPointAddressProvider(PATH_CER_WITHOUT_SLASH, PATH_NIC_CER_WITHOUT_SLASH);
    private static final DistributionPointAddressProvider SUT_WITHOUT_NIC_PREFIX =
        new DistributionPointAddressProvider(PATH_CER_WITH_SLASH);

    private static Stream<Arguments> getNicDeviceIdCertUrlParams() {
        return Stream.of(
            Arguments.of(NIC_PARAMS_FOR_MEV, EXPECTED_NIC_MEV_PATH),
            Arguments.of(NIC_PARAMS_FOR_CNV, EXPECTED_NIC_CNV_PATH),
            Arguments.of(NIC_PARAMS_FOR_LKV, EXPECTED_NIC_LKV_PATH)
        );
    }

    private static Stream<DistributionPointAddressProvider> getSuts() {
        return Stream.of(
            SUT,
            SUT_WITHOUT_SLASH,
            SUT_WITHOUT_NIC_PREFIX
        );
    }

    @ParameterizedTest
    @MethodSource(value = "getSuts")
    void getAttestationCertUrl(DistributionPointAddressProvider sut) {
        // when
        final String result = sut.getAttestationCertUrl(S10_PARAMS);

        // then
        assertEquals(EXPECTED_ATTESTATION_PATH, result);
    }

    @ParameterizedTest
    @MethodSource(value = "getSuts")
    void getDeviceIdCertUrl(DistributionPointAddressProvider sut) {
        // when
        final String result = sut.getDeviceIdCertUrl(DICE_PARAMS);

        // then
        assertEquals(EXPECTED_DEVICE_ID_PATH, result);
    }

    @ParameterizedTest
    @EnumSource(UdsChoice.class)
    void getDeviceIdCertUrl_WithUdsChoice(UdsChoice udsChoice) {
        // given
        final String expectedPath = EXPECTED_DEVICE_ID_PATH
            .replace(PATH_CER_WITH_SLASH, PATH_CER_WITH_SLASH + udsChoice.getDpSubDirectory() + "/");
        // when
        final String result = SUT.getDeviceIdCertUrl(udsChoice, DICE_PARAMS);

        // then
        assertEquals(expectedPath, result);
    }

    @ParameterizedTest
    @MethodSource(value = "getSuts")
    void getEnrollmentCertUrl(DistributionPointAddressProvider sut) {
        // when
        final String result = sut.getEnrollmentCertUrl(DICE_ENROLLMENT_PARAMS);

        // then
        assertEquals(EXPECTED_ENROLLMENT_PATH, result);
    }

    @ParameterizedTest
    @EnumSource(UdsChoice.class)
    void getEnrollmentCertUrl_WithUdsChoice(UdsChoice udsChoice) {
        // given
        final String expectedPath = EXPECTED_ENROLLMENT_PATH
            .replace(PATH_CER_WITH_SLASH, PATH_CER_WITH_SLASH + udsChoice.getDpSubDirectory() + "/");
        // when
        final String result = SUT.getEnrollmentCertUrl(udsChoice, DICE_ENROLLMENT_PARAMS);

        // then
        assertEquals(expectedPath, result);
    }

    @ParameterizedTest
    @MethodSource(value = "getSuts")
    void getIidUdsCertUrl(DistributionPointAddressProvider sut) {
        // when
        final String result = sut.getIidUdsCertUrl(DICE_PARAMS);

        // then
        assertEquals(EXPECTED_IID_UDS_PATH, result);
    }

    @ParameterizedTest
    @MethodSource(value = "getNicDeviceIdCertUrlParams")
    void getNicDeviceIdCertUrl_ReturnsExpected(NicDiceParams params, String expectedUrl) {
        // when
        final String result = SUT.getNicDeviceIdCertUrl(params);

        // then
        assertEquals(expectedUrl, result);
    }

    @ParameterizedTest
    @MethodSource(value = "getNicDeviceIdCertUrlParams")
    void getNicDeviceIdCertUrl_WithoutSlashInPrefix_ReturnsExpected(NicDiceParams params, String expectedUrl) {
        // when
        final String result = SUT_WITHOUT_SLASH.getNicDeviceIdCertUrl(params);

        // then
        assertEquals(expectedUrl, result);
    }

    @ParameterizedTest
    @MethodSource(value = "getNicDeviceIdCertUrlParams")
    void getNicDeviceIdCertUrl_WithoutNicPrefix_Throws(NicDiceParams params) {
        // when-then
        assertThrows(IllegalStateException.class, () -> SUT_WITHOUT_NIC_PREFIX.getNicDeviceIdCertUrl(params));
    }

    @Test
    void getRimSigningCertUrl_Success() {
        // given
        final String familyName = Family.AGILEX.getFamilyName();
        final String ski = "41SSZwl66ctC-wuR6nz5ggpzhTY";
        final String expected = PATH_CER_WITH_SLASH + "RIM_Signing_agilex_41SSZwl66ctC-wuR6nz5ggpzhTY.cer";
        final DistributionPointAddressProvider sut = new DistributionPointAddressProvider(PATH_CER_WITH_SLASH);

        // when
        final String actual = sut.getRimSigningCertUrl(new RimParams(ski, familyName));

        // then
        assertEquals(expected, actual);
    }

    @Test
    void getRimSignedDataUrl_Success() {
        // given
        final String expected = PATH_RIM_WITH_SLASH + "agilex_L1_Mog-JSb1TqIfv5lkKo9W54egMZ0d.corim";
        final String familyName = Family.AGILEX.getFamilyName();
        final String fwId = "Mog-JSb1TqIfv5lkKo9W54egMZ0d";
        final DistributionPointAddressProvider sut = new DistributionPointAddressProvider(PATH_RIM_WITH_SLASH);

        // when
        final String actual = sut.getRimSignedDataUrl(new RimSignedDataParams(familyName, "L1", fwId));

        // then
        assertEquals(expected, actual);
    }

    @Test
    void getXrimSignedDataUrl_Success() {
        // given
        final String familyName = Family.AGILEX.getFamilyName();
        final String ski = "41SSZwl66ctC-wuR6nz5ggpzhTY";
        final String expected = PATH_XRIM_WITH_SLASH + "RIM_Signing_agilex_41SSZwl66ctC-wuR6nz5ggpzhTY.xcorim";
        final DistributionPointAddressProvider sut = new DistributionPointAddressProvider(PATH_XRIM_WITH_SLASH);

        // when
        final String actual = sut.getXrimSignedDataUrl(new RimParams(ski, familyName));

        // then
        assertEquals(expected, actual);
    }
}
