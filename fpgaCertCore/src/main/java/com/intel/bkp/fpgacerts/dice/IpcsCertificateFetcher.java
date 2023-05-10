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

package com.intel.bkp.fpgacerts.dice;

import com.intel.bkp.fpgacerts.chain.DistributionPointCertificate;
import com.intel.bkp.fpgacerts.chain.ICertificateFetcher;
import com.intel.bkp.fpgacerts.dice.subject.DiceCertificateLevel;
import com.intel.bkp.fpgacerts.dice.subject.DiceCertificateSubject;
import com.intel.bkp.fpgacerts.exceptions.IpcsCertificateFetcherNotInitializedException;
import com.intel.bkp.fpgacerts.url.DistributionPointAddressProvider;
import com.intel.bkp.fpgacerts.url.params.DiceEnrollmentParams;
import com.intel.bkp.fpgacerts.url.params.DiceParams;
import com.intel.bkp.fpgacerts.url.params.parsing.DiceEnrollmentParamsIssuerParser;
import com.intel.bkp.fpgacerts.url.params.parsing.DiceParamsIssuerParser;
import com.intel.bkp.fpgacerts.url.params.parsing.DiceParamsSubjectParser;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.Optional;

@Slf4j
public class IpcsCertificateFetcher {

    private final ICertificateFetcher certificateFetcher;
    private final DistributionPointAddressProvider addressProvider;
    private final DiceParamsProvider paramsProvider;

    // Below certs are used as input, to determine URL parameters - at least one must be set
    private Optional<X509Certificate> firmwareCert;
    // one of certificates from level 0
    private Optional<X509Certificate> deviceIdL0Cert;

    // Below certs are results (fetched certs)
    // - if first (external) optional is empty, it means there was no attempt to fetch cert yet,
    // - if second (internal) optional is empty, it means that fetching already happened, but returned no cert
    //      (cert does not exist on distribution point)
    private Optional<Optional<DistributionPointCertificate>> ipcsDeviceIdCert;
    private Optional<Optional<DistributionPointCertificate>> ipcsEnrollmentCert;
    private Optional<Optional<DistributionPointCertificate>> ipcsIidUdsCert;

    public IpcsCertificateFetcher(ICertificateFetcher certificateFetcher, String certificateUrlPrefix) {
        this(certificateFetcher,
            new DiceParamsSubjectParser(),
            new DiceParamsIssuerParser(),
            new DiceEnrollmentParamsIssuerParser(),
            new DistributionPointAddressProvider(certificateUrlPrefix));
    }

    IpcsCertificateFetcher(ICertificateFetcher certificateFetcher,
                           DiceParamsSubjectParser diceParamsSubjectParser,
                           DiceParamsIssuerParser diceParamsIssuerParser,
                           DiceEnrollmentParamsIssuerParser diceEnrollmentParamsIssuerParser,
                           DistributionPointAddressProvider addressProvider) {
        this.certificateFetcher = certificateFetcher;
        this.addressProvider = addressProvider;
        this.paramsProvider = new DiceParamsProvider(
            diceParamsSubjectParser, diceParamsIssuerParser, diceEnrollmentParamsIssuerParser);
        clear();
    }

    /**
     * Clears state, by resetting input certificates (firmware and deviceIdEnrollment) and cached results of fetching
     * (deviceId, enrollment, iidUds).
     *
     * <p>Use it if you want to fetch certificates for different device than before, as an alternative to creating a new
     * instance of IpcsCertificateFetcher.
     */
    public void clear() {
        firmwareCert = Optional.empty();
        deviceIdL0Cert = Optional.empty();

        ipcsDeviceIdCert = Optional.empty();
        ipcsEnrollmentCert = Optional.empty();
        ipcsIidUdsCert = Optional.empty();
    }

    public void setFirmwareCert(@NonNull X509Certificate cert) {
        this.firmwareCert = Optional.of(cert);
    }

    public void setDeviceIdL0Cert(@NonNull X509Certificate cert) {
        this.deviceIdL0Cert = Optional.of(cert);
    }

    public Optional<DistributionPointCertificate> fetchIpcsDeviceIdCert() {
        ipcsDeviceIdCert = ipcsDeviceIdCert.or(() -> Optional.of(fetchIpcsDeviceIdCertInternal()));
        return ipcsDeviceIdCert.get();
    }

    private Optional<DistributionPointCertificate> fetchIpcsDeviceIdCertInternal() {
        final String url = addressProvider.getDeviceIdCertUrl(paramsProvider.getDeviceIdParams());
        return fetch(url);
    }

    public Optional<DistributionPointCertificate> fetchIpcsIidUdsCert() {
        ipcsIidUdsCert = ipcsIidUdsCert.or(() -> Optional.of(fetchIpcsIidUdsCertInternal()));
        return ipcsIidUdsCert.get();
    }

    private Optional<DistributionPointCertificate> fetchIpcsIidUdsCertInternal() {
        final String url = addressProvider.getIidUdsCertUrl(paramsProvider.getIidUdsParams());
        return fetch(url);
    }

    public Optional<DistributionPointCertificate> fetchIpcsEnrollmentCert() {
        ipcsEnrollmentCert = ipcsEnrollmentCert.or(() -> Optional.of(fetchIpcsEnrollmentCertInternal()));
        return ipcsEnrollmentCert.get();
    }

    private Optional<DistributionPointCertificate> fetchIpcsEnrollmentCertInternal() {
        final String url = addressProvider.getEnrollmentCertUrl(paramsProvider.getEnrollmentParams());
        return fetch(url);
    }

    private Optional<DistributionPointCertificate> fetch(String url) {
        final var fetchedCert = certificateFetcher.fetchCertificate(url)
            .map(cert -> new DistributionPointCertificate(url, cert));

        log.debug((fetchedCert.isPresent() ? "Fetched" : "Failed to fetch") + " certificate: " + url);

        return fetchedCert;
    }

    @RequiredArgsConstructor
    private class DiceParamsProvider {

        private final DiceParamsSubjectParser diceParamsSubjectParser;
        private final DiceParamsIssuerParser diceParamsIssuerParser;
        private final DiceEnrollmentParamsIssuerParser diceEnrollmentParamsIssuerParser;

        public DiceParams getDeviceIdParams() {
            return getDiceParamsBasedOnFirmwareCertIssuer()
                .or(this::getDiceParamsBasedOnDeviceIdL0CertSubject)
                .orElseThrow(this::getNoCertificatesException);
        }

        public DiceParams getIidUdsParams() {
            return getDiceParamsBasedOnDeviceIdEnrollmentCertIssuer()
                .orElseThrow(this::getNoDeviceIdEnrollmentCertificateException);
        }

        public DiceEnrollmentParams getEnrollmentParams() {
            return getEnrollmentParamsBasedOnDeviceIdEnrollmentCertIssuer()
                .orElseThrow(this::getNoDeviceIdEnrollmentCertificateException);
        }

        private Optional<DiceParams> getDiceParamsBasedOnFirmwareCertIssuer() {
            return firmwareCert
                .map(diceParamsIssuerParser::parse);
        }

        private Optional<DiceParams> getDiceParamsBasedOnDeviceIdL0CertSubject() {
            return deviceIdL0Cert
                .map(diceParamsSubjectParser::parse);
        }

        private Optional<DiceParams> getDiceParamsBasedOnDeviceIdEnrollmentCertIssuer() {
            return deviceIdL0Cert
                .filter(this::isDeviceIdEnrollmentCert)
                .map(diceParamsIssuerParser::parse);
        }

        private Optional<DiceEnrollmentParams> getEnrollmentParamsBasedOnDeviceIdEnrollmentCertIssuer() {
            return deviceIdL0Cert
                .filter(this::isDeviceIdEnrollmentCert)
                .map(diceEnrollmentParamsIssuerParser::parse);
        }

        private IpcsCertificateFetcherNotInitializedException getNoCertificatesException() {
            return new IpcsCertificateFetcherNotInitializedException(
                "Neither firmware nor any deviceId (L0) certificate were provided - failed to determine URL params.");
        }

        private IpcsCertificateFetcherNotInitializedException getNoDeviceIdEnrollmentCertificateException() {
            return new IpcsCertificateFetcherNotInitializedException(
                "DeviceIdEnrollment certificate was not provided - failed to determine URL params.");
        }

        private boolean isDeviceIdEnrollmentCert(X509Certificate cert) {
            final String issuer = cert.getIssuerX500Principal().getName();
            return DiceCertificateSubject.tryParse(issuer)
                .map(DiceCertificateSubject::level)
                .map(level -> level.equals(DiceCertificateLevel.ENROLLMENT.getCode()))
                .orElse(false);
        }

    }
}
