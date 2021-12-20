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

package com.intel.bkp.verifier.service.certificate;

import com.intel.bkp.verifier.model.dice.DiceEnrollmentParams;
import com.intel.bkp.verifier.model.dice.DiceParams;
import com.intel.bkp.verifier.model.s10.S10Params;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class DistributionPointAddressProviderTest {

    private static final String PATH_CER = "https://tsci.intel.com/content/IPCS/certs/";

    private static final S10Params S10_PARAMS = new S10Params("deviceId", "pufType");
    private static final DiceParams DICE_PARAMS = new DiceParams("skiInBase64", "UID");
    private static final DiceEnrollmentParams DICE_ENROLLMENT_PARAMS =
        new DiceEnrollmentParams("skiERinBase64", "SVN", "UID");

    private static final String EXPECTED_ATTESTATION_PATH = PATH_CER + "attestation_DEVICEID_PUFTYPE.cer";
    private static final String EXPECTED_DEVICE_ID_PATH = PATH_CER + "deviceid_uid_skiInBase64.cer";
    private static final String EXPECTED_ENROLLMENT_PATH = PATH_CER + "enrollment_uid_svn_skiERinBase64.cer";
    private static final String EXPECTED_IID_UDS_PATH = PATH_CER + "iiduds_uid_skiInBase64.cer";

    private DistributionPointAddressProvider sut = new DistributionPointAddressProvider(PATH_CER);

    @Test
    void getAttestationCertFilename() {
        // when
        final String result = sut.getAttestationCertFilename(S10_PARAMS);

        // then
        Assertions.assertEquals(EXPECTED_ATTESTATION_PATH, result);
    }

    @Test
    void getDeviceIdCertFilename() {
        // when
        final String result = sut.getDeviceIdCertFilename(DICE_PARAMS);

        // then
        Assertions.assertEquals(EXPECTED_DEVICE_ID_PATH, result);
    }

    @Test
    void getEnrollmentCertFilename() {
        // when
        final String result = sut.getEnrollmentCertFilename(DICE_ENROLLMENT_PARAMS);

        // then
        Assertions.assertEquals(EXPECTED_ENROLLMENT_PATH, result);
    }

    @Test
    void getIidUdsCertFilename() {
        // when
        final String result = sut.getIidUdsCertFilename(DICE_PARAMS);

        // then
        Assertions.assertEquals(EXPECTED_IID_UDS_PATH, result);
    }
}
