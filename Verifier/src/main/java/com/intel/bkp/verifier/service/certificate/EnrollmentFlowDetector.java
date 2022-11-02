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

import com.intel.bkp.fpgacerts.dice.IEnrollmentFlowDetector;
import com.intel.bkp.fpgacerts.dice.IpcsCertificateFetcher;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class EnrollmentFlowDetector implements IEnrollmentFlowDetector {

    private final byte[] deviceId;
    private final IpcsCertificateFetcher certFetcher;
    private final DiceRevocationCacheService diceRevocationCacheService;

    public static EnrollmentFlowDetector instance(byte[] deviceId, IpcsCertificateFetcher certFetcher) {
        return new EnrollmentFlowDetector(deviceId, certFetcher, new DiceRevocationCacheService());
    }

    @Override
    public boolean isEnrollmentFlow() {
        return isRevoked() || deviceIdCertificateNotFound();
    }

    private boolean isRevoked() {
        final boolean isRevoked = diceRevocationCacheService.isRevoked(deviceId);
        if (isRevoked) {
            logEnrollmentFlowDetected("device %s was previously cached as revoked.".formatted(toHex(deviceId)));
        }
        return isRevoked;
    }

    private boolean deviceIdCertificateNotFound() {
        final boolean notFound = certFetcher.fetchIpcsDeviceIdCert().isEmpty();
        if (notFound) {
            logEnrollmentFlowDetected("deviceId certificate not found.");
        }
        return notFound;
    }

    private void logEnrollmentFlowDetected(String details) {
        log.debug("Detected enrollment flow - {}", details);
    }
}
