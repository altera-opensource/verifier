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

import com.intel.bkp.core.command.model.CertificateRequestType;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.verifier.dp.DistributionPointIpcsCertificateFetcher;
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
import java.util.stream.Stream;

import static com.intel.bkp.core.command.model.CertificateRequestType.DEVICE_ID_ENROLLMENT;
import static com.intel.bkp.core.command.model.CertificateRequestType.UDS_EFUSE_ALIAS;
import static com.intel.bkp.core.command.model.CertificateRequestType.UDS_IID_PUF_ALIAS;
import static com.intel.bkp.verifier.x509.X509UtilsWrapper.toX509;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@NoArgsConstructor
public class GpDiceChainService {

    private final GpDeviceCertificateProvider gpDeviceCertificateProvider = new GpDeviceCertificateProvider();
    private final DistributionPointIpcsCertificateFetcher ipcsCertFetcher =
        new DistributionPointIpcsCertificateFetcher();
    private final IidAliasFlowDetector iidFlowDetector = new IidAliasFlowDetector();
    private GpDiceAttestationRevocationService diceAttestationRevocationService =
        new GpDiceAttestationRevocationService();
    private DiceRevocationCacheService diceRevocationCacheService = new DiceRevocationCacheService();
    private DiceChainMeasurementsCollector measurementsCollector = new DiceChainMeasurementsCollector();

    @Getter
    private PublicKey aliasPublicKey;

    @Getter
    private List<TcbInfoMeasurement> tcbInfoMeasurements = new ArrayList<>();

    public void fetchAndVerifyDiceChains(byte[] deviceId, byte[] firmwareCertificateResponse) {
        final List<X509Certificate> efuseChain = getEfuseChain(deviceId, firmwareCertificateResponse);
        final X509Certificate aliasX509 = efuseChain.get(0);
        final List<X509Certificate> iidChain = getIidChain(aliasX509);

        this.aliasPublicKey = aliasX509.getPublicKey();
        this.tcbInfoMeasurements = getTcbInfoMeasurements(efuseChain, iidChain);

        diceAttestationRevocationService.verifyChains(deviceId, efuseChain, iidChain);
    }

    private List<X509Certificate> getEfuseChain(byte[] deviceId, byte[] firmwareCertificateResponse) {
        final var aliasX509 = getCertificateFromDevice(UDS_EFUSE_ALIAS);
        final var firmwareX509 = toX509(firmwareCertificateResponse);
        final var deviceIdEnrollmentX509 = getCertificateFromDevice(DEVICE_ID_ENROLLMENT);

        prepareDistributionPointFetching(firmwareX509, deviceIdEnrollmentX509);

        if (EnrollmentFlowDetector.instance(deviceId, ipcsCertFetcher).isEnrollmentFlow()) {
            final var enrollmentX509 = ipcsCertFetcher.fetchIpcsEnrollmentX509Cert();
            diceRevocationCacheService.saveAsRevoked(deviceId);
            return List.of(aliasX509, firmwareX509, deviceIdEnrollmentX509, enrollmentX509);
        } else {
            final var deviceIdX509 = ipcsCertFetcher.fetchIpcsDeviceIdX509Cert();
            return List.of(aliasX509, firmwareX509, deviceIdX509);
        }
    }

    private List<X509Certificate> getIidChain(X509Certificate certWithUeidExtension) {
        if (!iidFlowDetector.isIidFlow(certWithUeidExtension)) {
            return List.of();
        }

        final var iidAliasX509 = getCertificateFromDevice(UDS_IID_PUF_ALIAS);
        final var iidUdsX509 = ipcsCertFetcher.fetchIpcsIidUdsX509Cert();

        return List.of(iidAliasX509, iidUdsX509);
    }

    private void prepareDistributionPointFetching(X509Certificate firmwareX509,
                                                  X509Certificate deviceIdEnrollmentX509) {
        ipcsCertFetcher.setFirmwareCert(firmwareX509);
        ipcsCertFetcher.setDeviceIdL0Cert(deviceIdEnrollmentX509);
    }

    private X509Certificate getCertificateFromDevice(CertificateRequestType certType) {
        return gpDeviceCertificateProvider.getCertificateFromDevice(certType);
    }

    private List<TcbInfoMeasurement> getTcbInfoMeasurements(List<X509Certificate> efuseChain,
                                                            List<X509Certificate> iidChain) {
        final var efuseChainMeasurements = measurementsCollector.getMeasurementsFromCertChain(efuseChain);
        final var iidChainMeasurements = measurementsCollector.getMeasurementsFromCertChain(iidChain);
        return Stream.concat(efuseChainMeasurements.stream(), iidChainMeasurements.stream()).toList();
    }
}
