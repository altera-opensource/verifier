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

import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoExtensionParser;
import com.intel.bkp.verifier.dp.DistributionPointIpcsCertificateFetcher;
import com.intel.bkp.verifier.exceptions.X509ParsingException;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509CertificateChain;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@NoArgsConstructor
public class SpdmDiceChainService {

    private final DistributionPointIpcsCertificateFetcher ipcsCertFetcher =
        new DistributionPointIpcsCertificateFetcher();
    private final IidAliasFlowDetector iidFlowDetector = new IidAliasFlowDetector();
    private DiceAttestationRevocationService diceAttestationRevocationService = new DiceAttestationRevocationService();
    private TcbInfoExtensionParser tcbInfoExtensionParser = new TcbInfoExtensionParser();
    private DiceRevocationCacheService diceRevocationCacheService = new DiceRevocationCacheService();

    @Getter
    private PublicKey aliasPublicKey;

    @Getter
    private List<TcbInfo> tcbInfos = new ArrayList<>();

    public void fetchAndVerifyDiceChains(byte[] deviceId, byte[] efuseChainResponse) {
        final List<X509Certificate> efuseChain = getEfuseChain(deviceId, efuseChainResponse);

        final X509Certificate aliasX509 = efuseChain.get(0);
        final List<X509Certificate> iidChain = getIidChain(aliasX509);

        this.aliasPublicKey = aliasX509.getPublicKey();
        this.tcbInfos = getTcbInfos(efuseChain);

        diceAttestationRevocationService.verifyChains(deviceId, efuseChain, iidChain);
    }

    private List<X509Certificate> getEfuseChain(byte[] deviceId, byte[] efuseChainResponse) {
        try {
            final List<X509Certificate> efuseChainFromDevice = toX509CertificateChain(efuseChainResponse);
            final EfuseChainParser efuseChainParser = EfuseChainParser.parseEfuseChain(efuseChainFromDevice);

            final var deviceIdX509 = efuseChainParser.getDeviceIdCert();
            final var firmwareX509 = efuseChainParser.getFirmwareCert();
            final var aliasX509 = efuseChainParser.getAliasCert();

            prepareDistributionPointFetching(firmwareX509, deviceIdX509);

            if (EnrollmentFlowDetector.instance(deviceId, ipcsCertFetcher).isEnrollmentFlow()) {
                final var enrollmentX509 = ipcsCertFetcher.fetchIpcsEnrollmentX509Cert();
                diceRevocationCacheService.saveAsRevoked(deviceId);
                return List.of(aliasX509, firmwareX509, deviceIdX509, enrollmentX509);
            } else {
                final var ipcsDeviceIdX509 = ipcsCertFetcher.fetchIpcsDeviceIdX509Cert();
                return List.of(aliasX509, firmwareX509, ipcsDeviceIdX509);
            }
        } catch (X509CertificateParsingException e) {
            throw new X509ParsingException("Failed to parse SPDM efuse chain of certificates.", e);
        }
    }

    private List<X509Certificate> getIidChain(X509Certificate certWithUeidExtension) {
        if (!iidFlowDetector.isIidFlow(certWithUeidExtension)) {
            return List.of();
        }

        log.debug("IID chain with SPDM not supported.");
        return List.of();
    }

    private void prepareDistributionPointFetching(X509Certificate firmwareX509,
                                                  X509Certificate deviceIdEnrollmentX509) {
        ipcsCertFetcher.setFirmwareCert(firmwareX509);
        ipcsCertFetcher.setDeviceIdL0Cert(deviceIdEnrollmentX509);
    }

    private List<TcbInfo> getTcbInfos(List<X509Certificate> chain) {
        return chain.stream()
            .map(tcbInfoExtensionParser::parse)
            .flatMap(Collection::stream)
            .toList();
    }
}
