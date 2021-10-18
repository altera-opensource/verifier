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

import com.intel.bkp.ext.core.utils.AttestationConstants;
import com.intel.bkp.verifier.model.IpcsDistributionPoint;
import com.intel.bkp.verifier.model.dice.DiceEnrollmentParams;
import com.intel.bkp.verifier.model.dice.DiceParams;
import com.intel.bkp.verifier.model.s10.S10Params;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@NoArgsConstructor
public class DistributionPointAddressProvider {

    private IpcsDistributionPoint dp;

    void withDistributionPoint(IpcsDistributionPoint dp) {
        this.dp = dp;
    }

    String getAttestationCertFilename(S10Params s10Params) {
        return dp.getPathCer() + String.format(AttestationConstants.S10_ATTESTATION_CERT_FILE_NAME,
            s10Params.getDeviceId(),
            s10Params.getPufType());
    }

    String getDeviceIdCertFilename(DiceParams diceParams) {
        return dp.getPathCer() + String.format(AttestationConstants.DEVICEID_CERT_FILE_NAME,
            diceParams.getUid(),
            diceParams.getSki());
    }

    String getEnrollmentCertFilename(DiceParams diceParams,
        DiceEnrollmentParams diceEnrollmentParams) {
        return dp.getPathCer() + String.format(AttestationConstants.ENROLLMENT_CERT_FILE_NAME,
            diceParams.getUid(),
            diceEnrollmentParams.getSvn(),
            diceEnrollmentParams.getSkiER());
    }

    String getIidUdsCertFilename(DiceParams diceParams) {
        return dp.getPathCer() + String.format(AttestationConstants.IIDUDS_CERT_FILE_NAME,
            diceParams.getUid(),
            diceParams.getSki());
    }
}
