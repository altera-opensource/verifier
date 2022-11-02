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

import com.intel.bkp.fpgacerts.dice.subject.DiceCertificateLevel;
import com.intel.bkp.fpgacerts.dice.subject.DiceCertificateSubject;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.dice.subject.DiceCertificateLevel.ALIAS;
import static com.intel.bkp.fpgacerts.dice.subject.DiceCertificateLevel.DEVICE_ID;
import static com.intel.bkp.fpgacerts.dice.subject.DiceCertificateLevel.FIRMWARE;

@Slf4j
@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class EfuseChainParser {

    private static final int MINIMUM_CERTIFICATES_SIZE = 3;
    private static final String CERT_NOT_FOUND = "Certificate from level %s not found.";
    private static final String INSUFFICIENT_CHAIN_SIZE = "Insufficient chain size from device: %d.";

    private final X509Certificate deviceIdCert;
    private final X509Certificate firmwareCert;
    private final X509Certificate aliasCert;

    static EfuseChainParser parseEfuseChain(List<X509Certificate> efuseChainFromDevice) {
        if (!hasSufficientSize(efuseChainFromDevice)) {
            throw new VerifierRuntimeException(INSUFFICIENT_CHAIN_SIZE.formatted(efuseChainFromDevice.size()));
        }

        final X509Certificate deviceIdCert = getCertificateByDiceLevel(efuseChainFromDevice, DEVICE_ID);
        final X509Certificate firmwareCert = getCertificateByDiceLevel(efuseChainFromDevice, FIRMWARE);
        final X509Certificate aliasCert = getCertificateByDiceLevel(efuseChainFromDevice, ALIAS);

        return new EfuseChainParser(deviceIdCert, firmwareCert, aliasCert);
    }

    private static X509Certificate getCertificateByDiceLevel(List<X509Certificate> efuseChainFromDevice,
                                                             DiceCertificateLevel diceCertificateLevel) {
        log.debug("Looking for certificate with DICE level: {}", diceCertificateLevel.getCode());
        return efuseChainFromDevice.stream()
            .filter(c -> hasExpectedDiceLevel(c, diceCertificateLevel))
            .findFirst()
            .orElseThrow(
                () -> new VerifierRuntimeException(CERT_NOT_FOUND.formatted(diceCertificateLevel.getCode()))
            );
    }

    private static boolean hasSufficientSize(List<X509Certificate> efuseChainFromDevice) {
        return MINIMUM_CERTIFICATES_SIZE <= efuseChainFromDevice.size();
    }

    private static boolean hasExpectedDiceLevel(X509Certificate cert, DiceCertificateLevel expectedLevel) {
        return getDiceCertificateLevel(cert)
            .map(level -> level.equals(expectedLevel))
            .orElse(false);
    }

    private static Optional<DiceCertificateLevel> getDiceCertificateLevel(X509Certificate certificate) {
        final String subject = certificate.getSubjectX500Principal().getName();
        return DiceCertificateSubject.tryParse(subject)
            .map(DiceCertificateSubject::getLevel)
            .map(DiceCertificateLevel::findByCode);
    }
}
