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

package com.intel.bkp.fpgacerts.dice;

import com.intel.bkp.fpgacerts.chain.DistributionPointCertificate;
import com.intel.bkp.fpgacerts.chain.ICertificateFetcher;
import com.intel.bkp.fpgacerts.exceptions.IpcsCertificateFetcherNotInitializedException;
import com.intel.bkp.fpgacerts.url.DistributionPointAddressProvider;
import com.intel.bkp.fpgacerts.url.params.DiceEnrollmentParams;
import com.intel.bkp.fpgacerts.url.params.DiceParams;
import com.intel.bkp.fpgacerts.url.params.parsing.DiceEnrollmentParamsIssuerParser;
import com.intel.bkp.fpgacerts.url.params.parsing.DiceParamsIssuerParser;
import com.intel.bkp.fpgacerts.url.params.parsing.DiceParamsSubjectParser;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class IpcsCertificateFetcher {

    private final ICertificateFetcher certificateFetcher;
    private final DiceParamsSubjectParser diceParamsSubjectParser;
    private final DiceParamsIssuerParser diceParamsIssuerParser;
    private final DiceEnrollmentParamsIssuerParser diceEnrollmentParamsIssuerParser;
    private final DistributionPointAddressProvider addressProvider;

    // Below certs are used as input, to determine URL parameters - at least one must be set
    private Optional<X509Certificate> firmwareCert;
    private Optional<X509Certificate> deviceIdEnrollmentCert;

    // Below certs are results (fetched certs)
    // - if first (external) optional is empty, it means there was no attempt to fetch cert yet,
    // - if second (internal) optional is empty, it means that fetching already happened, but returned no cert
    //      (cert does not exist on distribution point)
    private Optional<Optional<DistributionPointCertificate>> deviceIdCert;
    private Optional<Optional<DistributionPointCertificate>> enrollmentCert;
    private Optional<Optional<DistributionPointCertificate>> iidUdsCert;

    public IpcsCertificateFetcher(ICertificateFetcher certificateFetcher, String certificateUrlPrefix) {
        this(certificateFetcher, new DiceParamsSubjectParser(), new DiceParamsIssuerParser(),
            new DiceEnrollmentParamsIssuerParser(), new DistributionPointAddressProvider(certificateUrlPrefix));
        clear();
    }

    /**
     * Clears state, by resetting input certificates (firmware and deviceIdEnrollment) and cached results of fetching
     * (deviceId, enrollment, iidUds).
     *
     * <p>Use it if you want to fetch certificates for different device than before, as an alternative to creating a new
     * instance of IpcsCertificateFetcher.
     */
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
    public void clear() {
        firmwareCert = Optional.empty();
        deviceIdEnrollmentCert = Optional.empty();

        deviceIdCert = Optional.empty();
        enrollmentCert = Optional.empty();
        iidUdsCert = Optional.empty();
    }

    public void setFirmwareCert(@NonNull X509Certificate cert) {
        this.firmwareCert = Optional.of(cert);
    }

    public void setDeviceIdEnrollmentCert(@NonNull X509Certificate cert) {
        this.deviceIdEnrollmentCert = Optional.of(cert);
    }

    public Optional<DistributionPointCertificate> fetchDeviceIdCert() {
        deviceIdCert = deviceIdCert.or(() -> Optional.of(fetchDeviceIdCert(getDiceParams())));
        return deviceIdCert.get();
    }

    private Optional<DistributionPointCertificate> fetchDeviceIdCert(DiceParams diceParams) {
        final String url = addressProvider.getDeviceIdCertUrl(diceParams);
        return fetch(url);
    }

    public Optional<DistributionPointCertificate> fetchIidUdsCert() {
        iidUdsCert = iidUdsCert.or(() -> Optional.of(fetchIidUdsCert(getDiceParams())));
        return iidUdsCert.get();
    }

    private Optional<DistributionPointCertificate> fetchIidUdsCert(DiceParams diceParams) {
        final String url = addressProvider.getIidUdsCertUrl(diceParams);
        return fetch(url);
    }

    public Optional<DistributionPointCertificate> fetchEnrollmentCert() {
        enrollmentCert = enrollmentCert.or(() -> Optional.of(fetchEnrollmentCert(getDiceEnrollmentParams())));
        return enrollmentCert.get();
    }

    private Optional<DistributionPointCertificate> fetchEnrollmentCert(DiceEnrollmentParams diceEnrollmentParams) {
        final String url = addressProvider.getEnrollmentCertUrl(diceEnrollmentParams);
        return fetch(url);
    }

    private DiceParams getDiceParams() {
        return getDiceParamsBasedOnFirmwareCertIssuer()
            .or(this::getDiceParamsBasedOnDeviceIdEnrollmentCertSubject)
            .orElseThrow(this::getNoCertificatesException);
    }

    private Optional<DiceParams> getDiceParamsBasedOnFirmwareCertIssuer() {
        return firmwareCert
            .map(diceParamsIssuerParser::parse);
    }

    private Optional<DiceParams> getDiceParamsBasedOnDeviceIdEnrollmentCertSubject() {
        return deviceIdEnrollmentCert
            .map(diceParamsSubjectParser::parse);
    }

    private DiceEnrollmentParams getDiceEnrollmentParams() {
        return getEnrollmentParamsBasedOnDeviceIdEnrollmentCertIssuer()
            .orElseThrow(this::getNoDeviceIdCertificateException);
    }

    private Optional<DiceEnrollmentParams> getEnrollmentParamsBasedOnDeviceIdEnrollmentCertIssuer() {
        return deviceIdEnrollmentCert
            .map(diceEnrollmentParamsIssuerParser::parse);
    }

    private Optional<DistributionPointCertificate> fetch(String url) {
        final var fetchedCert = certificateFetcher.fetchCertificate(url)
            .map(cert -> new DistributionPointCertificate(url, cert));

        log.info((fetchedCert.isPresent() ? "Fetched" : "Failed to fetch") + " certificate: " + url);

        return fetchedCert;
    }

    private IpcsCertificateFetcherNotInitializedException getNoCertificatesException() {
        return new IpcsCertificateFetcherNotInitializedException(
            "Neither firmware nor deviceIdEnrollment certificate were provided - failed to determine URL params.");
    }

    private IpcsCertificateFetcherNotInitializedException getNoDeviceIdCertificateException() {
        return new IpcsCertificateFetcherNotInitializedException(
            "DeviceIdEnrollment certificate was not provided - failed to determine enrollment URL params.");
    }
}
