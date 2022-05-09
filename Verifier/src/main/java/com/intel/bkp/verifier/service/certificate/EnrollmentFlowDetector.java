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

package com.intel.bkp.verifier.service.certificate;

import com.intel.bkp.fpgacerts.chain.DistributionPointCertificate;
import com.intel.bkp.fpgacerts.dice.IEnrollmentFlowDetector;
import com.intel.bkp.fpgacerts.dice.IpcsCertificateFetcher;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

import java.security.cert.X509Certificate;
import java.util.Optional;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class EnrollmentFlowDetector implements IEnrollmentFlowDetector {
    private final byte[] deviceId;
    private final IpcsCertificateFetcher certFetcher;
    private final DiceRevocationCacheService diceRevocationCacheService;

    public static EnrollmentFlowDetector instance(X509Certificate firmwareCert, byte[] deviceId,
                                                  IpcsCertificateFetcher certFetcher) {
        certFetcher.setFirmwareCert(firmwareCert);
        return new EnrollmentFlowDetector(deviceId, certFetcher, new DiceRevocationCacheService());
    }

    @Override
    public boolean isEnrollmentFlow() {
        return isRevoked() || getDeviceIdCertificate().isEmpty();
    }

    private boolean isRevoked() {
        return diceRevocationCacheService.isRevoked(deviceId);
    }

    private Optional<DistributionPointCertificate> getDeviceIdCertificate() {
        return certFetcher.fetchDeviceIdCert();
    }
}
