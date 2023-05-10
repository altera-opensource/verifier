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

import com.intel.bkp.fpgacerts.model.SmartNicFamily;
import com.intel.bkp.fpgacerts.url.params.DiceEnrollmentParams;
import com.intel.bkp.fpgacerts.url.params.DiceParams;
import com.intel.bkp.fpgacerts.url.params.NicDiceParams;
import com.intel.bkp.fpgacerts.url.params.S10Params;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class DistributionPointAddressProviderTest {

    private static final String PATH_CER_WITH_SLASH = "https://tsci.intel.com/content/IPCS/certs/";
    private static final String PATH_CER_WITHOUT_SLASH = "https://tsci.intel.com/content/IPCS/certs";

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
    private static final String EXPECTED_NIC_MEV_PATH = PATH_CER_WITH_SLASH + "01_uid.cer";
    private static final String EXPECTED_NIC_LKV_PATH = PATH_CER_WITH_SLASH + "02_uid_skiInBase64.cer";
    private static final String EXPECTED_NIC_CNV_PATH = PATH_CER_WITH_SLASH + "03_uid_skiInBase64.cer";

    private final DistributionPointAddressProvider sut = new DistributionPointAddressProvider(PATH_CER_WITH_SLASH);
    private final DistributionPointAddressProvider sutWithoutSlash =
        new DistributionPointAddressProvider(PATH_CER_WITHOUT_SLASH);

    @Test
    void getAttestationCertUrl() {
        // when
        final String result = sut.getAttestationCertUrl(S10_PARAMS);

        // then
        Assertions.assertEquals(EXPECTED_ATTESTATION_PATH, result);
    }

    @Test
    void getAttestationCertUrl_WithoutSlash_AddsSlash() {
        // when
        final String result = sutWithoutSlash.getAttestationCertUrl(S10_PARAMS);

        // then
        Assertions.assertEquals(EXPECTED_ATTESTATION_PATH, result);
    }

    @Test
    void getDeviceIdCertUrl() {
        // when
        final String result = sut.getDeviceIdCertUrl(DICE_PARAMS);

        // then
        Assertions.assertEquals(EXPECTED_DEVICE_ID_PATH, result);
    }

    @Test
    void getDeviceIdCertUrl_WithoutSlash_AddsSlash() {
        // when
        final String result = sutWithoutSlash.getDeviceIdCertUrl(DICE_PARAMS);

        // then
        Assertions.assertEquals(EXPECTED_DEVICE_ID_PATH, result);
    }

    @Test
    void getEnrollmentCertUrl() {
        // when
        final String result = sut.getEnrollmentCertUrl(DICE_ENROLLMENT_PARAMS);

        // then
        Assertions.assertEquals(EXPECTED_ENROLLMENT_PATH, result);
    }

    @Test
    void getEnrollmentCertUrl_WithoutSlash_AddsSlash() {
        // when
        final String result = sutWithoutSlash.getEnrollmentCertUrl(DICE_ENROLLMENT_PARAMS);

        // then
        Assertions.assertEquals(EXPECTED_ENROLLMENT_PATH, result);
    }

    @Test
    void getIidUdsCertUrl() {
        // when
        final String result = sut.getIidUdsCertUrl(DICE_PARAMS);

        // then
        Assertions.assertEquals(EXPECTED_IID_UDS_PATH, result);
    }

    @Test
    void getIidUdsCertUrl_WithoutSlash_AddsSlash() {
        // when
        final String result = sutWithoutSlash.getIidUdsCertUrl(DICE_PARAMS);

        // then
        Assertions.assertEquals(EXPECTED_IID_UDS_PATH, result);
    }

    @Test
    void getNicDeviceIdCertUrl_ForMev_WithoutSkiInFileName() {
        // when
        final String result = sut.getNicDeviceIdCertUrl(NIC_PARAMS_FOR_MEV);

        // then
        Assertions.assertEquals(EXPECTED_NIC_MEV_PATH, result);
    }

    @Test
    void getNicDeviceIdCertUrl_ForLkv_WithSkiInFileName() {
        // when
        final String result = sut.getNicDeviceIdCertUrl(NIC_PARAMS_FOR_LKV);

        // then
        Assertions.assertEquals(EXPECTED_NIC_LKV_PATH, result);
    }

    @Test
    void getNicDeviceIdCertUrl_ForCnv_WithSkiInFileName() {
        // when
        final String result = sut.getNicDeviceIdCertUrl(NIC_PARAMS_FOR_CNV);

        // then
        Assertions.assertEquals(EXPECTED_NIC_CNV_PATH, result);
    }
}
