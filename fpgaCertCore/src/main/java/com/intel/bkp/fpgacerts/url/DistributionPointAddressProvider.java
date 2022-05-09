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

package com.intel.bkp.fpgacerts.url;

import com.intel.bkp.fpgacerts.url.filename.DeviceIdCertificateNameProvider;
import com.intel.bkp.fpgacerts.url.filename.EnrollmentCertificateNameProvider;
import com.intel.bkp.fpgacerts.url.filename.ICertificateFileNameProvider;
import com.intel.bkp.fpgacerts.url.filename.IidUdsCertificateNameProvider;
import com.intel.bkp.fpgacerts.url.filename.S10CertificateNameProvider;
import com.intel.bkp.fpgacerts.url.params.DiceEnrollmentParams;
import com.intel.bkp.fpgacerts.url.params.DiceParams;
import com.intel.bkp.fpgacerts.url.params.S10Params;
import com.intel.bkp.utils.PathUtils;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
@RequiredArgsConstructor
public class DistributionPointAddressProvider {

    private final String certificateUrlPrefix;

    public String getAttestationCertUrl(S10Params s10Params) {
        return getUrl(new S10CertificateNameProvider(s10Params));
    }

    public String getDeviceIdCertUrl(DiceParams diceParams) {
        return getUrl(new DeviceIdCertificateNameProvider(diceParams));
    }

    public String getEnrollmentCertUrl(DiceEnrollmentParams diceEnrollmentParams) {
        return getUrl(new EnrollmentCertificateNameProvider(diceEnrollmentParams));
    }

    public String getIidUdsCertUrl(DiceParams diceParams) {
        return getUrl(new IidUdsCertificateNameProvider(diceParams));
    }

    private String getUrl(ICertificateFileNameProvider fileNameProvider) {
        return PathUtils.buildPath(certificateUrlPrefix, fileNameProvider.getFileName());
    }
}
