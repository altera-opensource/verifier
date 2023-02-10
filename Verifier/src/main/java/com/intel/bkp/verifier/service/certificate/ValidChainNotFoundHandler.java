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
import com.intel.bkp.fpgacerts.chain.DistributionPointCertificate;
import com.intel.bkp.fpgacerts.dice.IpcsCertificateFetcher;
import com.intel.bkp.verifier.dp.DistributionPointCertificateFetcher;
import com.intel.bkp.verifier.dp.DistributionPointChainFetcher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.core.command.model.CertificateRequestType.DEVICE_ID_ENROLLMENT;
import static com.intel.bkp.fpgacerts.chain.DistributionPointCertificate.getUrls;

@Slf4j
@RequiredArgsConstructor
public class ValidChainNotFoundHandler {

    private static final String LOG_DELIMITER = "\n\t";
    private static final String TRUSTED_ROOT_NOT_FOUND_MESSAGE =
        "Valid chain on device not found. Refer to the Verifier logs "
            + "to download valid Intel DICE chain for your device. Put the chain into one of the slots using "
            + "SPDM SET_CERTIFICATE command.";

    private final GpDeviceCertificateProvider gpDeviceCertificateProvider;
    private final IpcsCertificateFetcher ipcsCertFetcher;
    private final DistributionPointChainFetcher chainFetcher;
    private final DiceRevocationCacheService diceRevocationCacheService;
    private final IidAliasFlowDetector iidFlowDetector;

    public ValidChainNotFoundHandler() {
        this(AppContext.instance());
    }

    ValidChainNotFoundHandler(AppContext appContext) {
        this(new GpDeviceCertificateProvider(),
            new IpcsCertificateFetcher(
                new DistributionPointCertificateFetcher(appContext.getDpConnector()), appContext.getDpPathCer()),
            new DistributionPointChainFetcher(appContext.getDpConnector()),
            new DiceRevocationCacheService(),
            new IidAliasFlowDetector());
    }

    public void run(byte[] deviceId) {
        try {
            log.debug("Running fallback with printing user message how to correctly perform device onboarding.");

            final var deviceIdEnrollmentX509 = getCertificateFromDevice(DEVICE_ID_ENROLLMENT);
            prepareDistributionPointFetching(deviceIdEnrollmentX509);

            logEfuseChain(deviceId);
            logIidChain(deviceIdEnrollmentX509);
        } catch (Exception e) {
            log.error("Exception occurred during preparing valid chain: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
        } finally {
            log.error(TRUSTED_ROOT_NOT_FOUND_MESSAGE);
        }
    }

    private void logEfuseChain(byte[] deviceId) {
        final Optional<DistributionPointCertificate> firstCert;
        if (EnrollmentFlowDetector.instance(deviceId, ipcsCertFetcher).isEnrollmentFlow()) {
            firstCert = ipcsCertFetcher.fetchIpcsEnrollmentCert();
            diceRevocationCacheService.saveAsRevoked(deviceId);
        } else {
            firstCert = ipcsCertFetcher.fetchIpcsDeviceIdCert();
        }

        firstCert.ifPresentOrElse(this::logUserMessageForEfuseChain,
            () -> log.debug("Failed to download EFUSE certificate chain."));
    }

    private void logIidChain(X509Certificate certWithUeidExtension) {
        if (iidFlowDetector.isIidFlow(certWithUeidExtension)) {
            final Optional<DistributionPointCertificate> firstCert = ipcsCertFetcher.fetchIpcsIidUdsCert();

            firstCert.ifPresentOrElse(this::logUserMessageForIidChain,
                () -> log.debug("Failed to download IID certificate chain."));
        }
    }

    private void logUserMessageForEfuseChain(DistributionPointCertificate distributionPointCertificate) {
        final var certChain = chainFetcher.downloadCertificateChain(distributionPointCertificate);

        log.error("If you use eFuse UDS, build .bin file based on below authority chain:{}{}",
            LOG_DELIMITER, String.join(LOG_DELIMITER, getUrls(certChain)));
    }

    private void logUserMessageForIidChain(DistributionPointCertificate distributionPointCertificate) {
        final var certChain = chainFetcher.downloadCertificateChain(distributionPointCertificate);

        log.error("If you use UDS IID:"
                + "\n- activate PUF using:{}{}"
                + "\n- build .bin file based on below authority chain:{}{}",
            LOG_DELIMITER, getIidUdsPufPath(certChain),
            LOG_DELIMITER, String.join(LOG_DELIMITER, getUrls(certChain)));
    }

    private String getIidUdsPufPath(List<DistributionPointCertificate> certChain) {
        return getUrls(certChain)
            .stream()
            .filter(s -> s.contains("iiduds_"))
            .findFirst()
            .map(s -> s
                .replace("/certs/", "/pufs/")
                .replace(".cer", ".puf")
            )
            .orElse("iiduds cert not found");
    }

    private X509Certificate getCertificateFromDevice(CertificateRequestType certType) {
        return gpDeviceCertificateProvider.getCertificateFromDevice(certType);
    }

    private void prepareDistributionPointFetching(X509Certificate deviceIdEnrollmentX509) {
        ipcsCertFetcher.setDeviceIdL0Cert(deviceIdEnrollmentX509);
    }
}
