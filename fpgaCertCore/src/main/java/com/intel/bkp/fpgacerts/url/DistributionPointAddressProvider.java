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
import com.intel.bkp.fpgacerts.model.UdsChoice;
import com.intel.bkp.fpgacerts.url.filename.DeviceIdCertificateNameProvider;
import com.intel.bkp.fpgacerts.url.filename.EnrollmentCertificateNameProvider;
import com.intel.bkp.fpgacerts.url.filename.ICertificateFileNameProvider;
import com.intel.bkp.fpgacerts.url.filename.IidUdsCertificateNameProvider;
import com.intel.bkp.fpgacerts.url.filename.NicDeviceIdCertificateNameProvider;
import com.intel.bkp.fpgacerts.url.filename.NicMevDeviceIdCertificateNameProvider;
import com.intel.bkp.fpgacerts.url.filename.RimCertificateNameProvider;
import com.intel.bkp.fpgacerts.url.filename.RimSignedDataNameProvider;
import com.intel.bkp.fpgacerts.url.filename.S10CertificateNameProvider;
import com.intel.bkp.fpgacerts.url.filename.XrimDataNameProvider;
import com.intel.bkp.fpgacerts.url.filename.ZipDiceNameProvider;
import com.intel.bkp.fpgacerts.url.params.DiceEnrollmentParams;
import com.intel.bkp.fpgacerts.url.params.DiceParams;
import com.intel.bkp.fpgacerts.url.params.NicDiceParams;
import com.intel.bkp.fpgacerts.url.params.RimParams;
import com.intel.bkp.fpgacerts.url.params.RimSignedDataParams;
import com.intel.bkp.fpgacerts.url.params.S10Params;
import com.intel.bkp.fpgacerts.url.params.ZipDiceParams;
import com.intel.bkp.utils.PathUtils;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.function.Function;

@Slf4j
@Getter
@RequiredArgsConstructor
public class DistributionPointAddressProvider {

    private final String ipcsUrlPrefix;

    private final String nicUrlPrefix;

    public DistributionPointAddressProvider(String ipcsUrlPrefix) {
        this(ipcsUrlPrefix, null);
    }

    public String getZipUrl(ZipDiceParams zipDiceParams) {
        return getIpcsUrl(new ZipDiceNameProvider(zipDiceParams));
    }

    public String getAttestationCertUrl(S10Params s10Params) {
        return getIpcsUrl(new S10CertificateNameProvider(s10Params));
    }

    public String getDeviceIdCertUrl(DiceParams diceParams) {
        return getIpcsUrl(new DeviceIdCertificateNameProvider(diceParams));
    }

    public String getDeviceIdCertUrl(UdsChoice udsChoice, DiceParams diceParams) {
        return getIpcsUrl(udsChoice.getDpSubDirectory(), new DeviceIdCertificateNameProvider(diceParams));
    }

    public String getRimSigningCertUrl(RimParams rimParams) {
        return getIpcsUrl(new RimCertificateNameProvider(rimParams));
    }

    public String getRimSignedDataUrl(RimSignedDataParams rimParams) {
        return getIpcsUrl(new RimSignedDataNameProvider(rimParams));
    }

    public String getXrimSignedDataUrl(RimParams rimParams) {
        return getIpcsUrl(new XrimDataNameProvider(rimParams));
    }

    public String getNicDeviceIdCertUrl(NicDiceParams params) {
        if (StringUtils.isBlank(nicUrlPrefix)) {
            throw new IllegalStateException("NIC certificate url prefix not configured.");
        }

        final Function<NicDiceParams, ICertificateFileNameProvider> nameProviderCtr =
            SmartNicFamily.MEV.equals(params.getFamily())
            ? NicMevDeviceIdCertificateNameProvider::new
            : NicDeviceIdCertificateNameProvider::new;
        return getNicUrl(nameProviderCtr.apply(params));
    }

    public String getEnrollmentCertUrl(DiceEnrollmentParams diceEnrollmentParams) {
        return getIpcsUrl(new EnrollmentCertificateNameProvider(diceEnrollmentParams));
    }

    public String getEnrollmentCertUrl(UdsChoice udsChoice, DiceEnrollmentParams diceEnrollmentParams) {
        return getIpcsUrl(udsChoice.getDpSubDirectory(), new EnrollmentCertificateNameProvider(diceEnrollmentParams));
    }

    public String getIidUdsCertUrl(DiceParams diceParams) {
        return getIpcsUrl(new IidUdsCertificateNameProvider(diceParams));
    }

    private String getIpcsUrl(ICertificateFileNameProvider fileNameProvider) {
        return getUrl(ipcsUrlPrefix, fileNameProvider);
    }

    private String getIpcsUrl(String subDir, ICertificateFileNameProvider fileNameProvider) {
        return getUrl(PathUtils.buildPath(ipcsUrlPrefix, subDir), fileNameProvider);
    }

    private String getNicUrl(ICertificateFileNameProvider fileNameProvider) {
        return getUrl(nicUrlPrefix, fileNameProvider);
    }

    private String getUrl(String prefix, ICertificateFileNameProvider fileNameProvider) {
        return PathUtils.buildPath(prefix, fileNameProvider.getFileName());
    }
}
