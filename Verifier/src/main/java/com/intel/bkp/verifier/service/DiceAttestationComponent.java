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

package com.intel.bkp.verifier.service;

import com.intel.bkp.core.command.model.CertificateRequestType;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoAggregator;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoExtensionParser;
import com.intel.bkp.verifier.dp.DistributionPointIpcsCertificateFetcher;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.service.certificate.DeviceCertificateProvider;
import com.intel.bkp.verifier.service.certificate.DiceAttestationRevocationService;
import com.intel.bkp.verifier.service.certificate.DiceRevocationCacheService;
import com.intel.bkp.verifier.service.certificate.EnrollmentFlowDetector;
import com.intel.bkp.verifier.service.certificate.IidAliasFlowDetector;
import com.intel.bkp.verifier.service.measurements.DeviceMeasurementsProvider;
import com.intel.bkp.verifier.service.measurements.DeviceMeasurementsRequest;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import static com.intel.bkp.core.command.model.CertificateRequestType.DEVICE_ID_ENROLLMENT;
import static com.intel.bkp.core.command.model.CertificateRequestType.UDS_EFUSE_ALIAS;
import static com.intel.bkp.core.command.model.CertificateRequestType.UDS_IID_PUF_ALIAS;
import static com.intel.bkp.verifier.x509.X509UtilsWrapper.toX509;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@NoArgsConstructor
public class DiceAttestationComponent {

    private final DeviceCertificateProvider deviceCertificateProvider = new DeviceCertificateProvider();
    private final DeviceMeasurementsProvider deviceMeasurementsProvider = new DeviceMeasurementsProvider();
    private final DistributionPointIpcsCertificateFetcher ipcsCertFetcher =
        new DistributionPointIpcsCertificateFetcher();
    private final IidAliasFlowDetector iidFlowDetector = new IidAliasFlowDetector();
    private DiceAttestationRevocationService diceAttestationRevocationService = new DiceAttestationRevocationService();
    private TcbInfoExtensionParser tcbInfoExtensionParser = new TcbInfoExtensionParser();
    private EvidenceVerifier evidenceVerifier = new EvidenceVerifier();
    private TcbInfoAggregator tcbInfoAggregator = new TcbInfoAggregator();
    private DiceRevocationCacheService diceRevocationCacheService = new DiceRevocationCacheService();

    public VerifierExchangeResponse perform(byte[] firmwareCertificateResponse, String refMeasurement,
                                            byte[] deviceId) {

        diceAttestationRevocationService.withDeviceId(deviceId);

        final X509Certificate aliasX509 = getCertificateFromDevice(UDS_EFUSE_ALIAS);
        parseTcbInfoAndAddToChain(aliasX509);

        final X509Certificate firmwareX509 = toX509(firmwareCertificateResponse);
        parseTcbInfoAndAddToChain(firmwareX509);

        if (EnrollmentFlowDetector.instance(firmwareX509, deviceId, ipcsCertFetcher).isEnrollmentFlow()) {
            runEnrollmentCertFlow(deviceId);
        } else {
            runDeviceIdCertFlow();
        }

        PufType pufType = PufType.EFUSE;
        if (iidFlowDetector.isIidFlow(firmwareX509)) {
            runIidCertFlow();
            pufType = PufType.IID;
        }

        diceAttestationRevocationService.verifyChains();

        tcbInfoAggregator.add(getMeasurementsFromDevice(aliasX509.getPublicKey(), deviceId, pufType));

        return evidenceVerifier.verify(tcbInfoAggregator, refMeasurement);
    }

    private List<TcbInfo> getMeasurementsFromDevice(PublicKey aliasKey, byte[] deviceId, PufType pufType) {
        final var measurementsRequest = DeviceMeasurementsRequest.forDice(deviceId, aliasKey, pufType);
        return deviceMeasurementsProvider.getMeasurementsFromDevice(measurementsRequest);
    }

    private void parseTcbInfoAndAddToChain(X509Certificate certificate) {
        tcbInfoAggregator.add(tcbInfoExtensionParser.parse(certificate));
        diceAttestationRevocationService.add(certificate);
    }

    private X509Certificate getCertificateFromDevice(CertificateRequestType certType) {
        return deviceCertificateProvider.getCertificateFromDevice(certType);
    }

    private void runDeviceIdCertFlow() {
        ipcsCertFetcher
            .fetchDeviceIdX509Cert()
            .ifPresentOrElse(this::parseTcbInfoAndAddToChain,
                () -> {
                    throw new InternalLibraryException("DeviceId certificate not found on Distribution Point.");
                }
            );
    }

    private void runEnrollmentCertFlow(byte[] deviceId) {

        log.debug("DeviceID cert not found on Distribution Point.");
        final X509Certificate enrollmentX509 = getCertificateFromDevice(DEVICE_ID_ENROLLMENT);
        parseTcbInfoAndAddToChain(enrollmentX509);

        ipcsCertFetcher.setDeviceIdEnrollmentCert(enrollmentX509);
        ipcsCertFetcher.fetchEnrollmentX509Cert()
            .ifPresentOrElse(this::parseTcbInfoAndAddToChain,
                () -> {
                    throw new InternalLibraryException("IPCS Enrollment certificate not found on Distribution Point.");
                }
            );

        diceRevocationCacheService.saveAsRevoked(deviceId);
    }

    private void runIidCertFlow() {
        diceAttestationRevocationService.addIid(getCertificateFromDevice(UDS_IID_PUF_ALIAS));

        ipcsCertFetcher
            .fetchIidUdsX509Cert()
            .ifPresentOrElse(diceAttestationRevocationService::addIid,
                () -> {
                    throw new InternalLibraryException("IID UDS certificate not found on Distribution Point.");
                }
            );
    }
}
