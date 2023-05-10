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

package com.intel.bkp.fpgacerts.verification;

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoExtensionParser;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfo;
import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static com.intel.bkp.crypto.x509.utils.X509CrlUtils.getX509CRLEntries;
import static com.intel.bkp.crypto.x509.utils.X509CrlUtils.isRevoked;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoExtensionParser.containsTcbInfoExtension;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement.asMeasurements;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement.containsAllReferenceMeasurements;

@Slf4j
public class DiceCrlVerifier extends CrlVerifier {

    public static final String TCB_INFO_REVOCATION_REASON = "TcbInfo";
    private final TcbInfoExtensionParser extensionParser;

    public DiceCrlVerifier(ICrlProvider crlProvider) {
        this(crlProvider, new TcbInfoExtensionParser());
    }

    DiceCrlVerifier(ICrlProvider crlProvider, TcbInfoExtensionParser extensionParser) {
        super(crlProvider);
        this.extensionParser = extensionParser;
    }

    @Override
    protected Optional<String> getRevocationReason(X509CRL crl, X509Certificate cert) {
        return super.getRevocationReason(crl, cert)
            .or(() -> isRevokedByTcbInfo(crl, cert)
                      ? Optional.of(TCB_INFO_REVOCATION_REASON)
                      : Optional.empty());
    }

    @Override
    protected boolean isRevokedBySerialNumber(X509CRL crl, X509Certificate cert) {
        return isRevoked(getCrlEntriesWithoutTcbInfoExtension(crl), cert.getSerialNumber());
    }

    private boolean isRevokedByTcbInfo(X509CRL crl, X509Certificate certificate) {
        if (!containsTcbInfoExtension(certificate)) {
            return false;
        }

        final List<TcbInfoMeasurement> measurementsFromCertificate = asMeasurements(extensionParser.parse(certificate));
        final Optional<List<TcbInfoMeasurement>> subsetOfMeasurementsFromCertificate =
            getCrlEntriesWithTcbInfoExtension(crl)
                .map(extensionParser::parse)
                .map(TcbInfoMeasurement::asMeasurements)
                .map(this::setDefaultVendorInfoMask)
                .filter(measurementsFromCrlEntry ->
                    containsAllReferenceMeasurements(measurementsFromCertificate, measurementsFromCrlEntry))
                .findFirst();

        subsetOfMeasurementsFromCertificate.ifPresent(subset ->
            logFoundSubset(measurementsFromCertificate, subset));

        return subsetOfMeasurementsFromCertificate.isPresent();
    }

    private List<TcbInfoMeasurement> setDefaultVendorInfoMask(List<TcbInfoMeasurement> tcbInfoMeasurements) {
        tcbInfoMeasurements.forEach(
            m -> m.getValue()
                .getMaskedVendorInfo()
                .ifPresent(MaskedVendorInfo::setMaskBasedOnVendorInfo)
        );
        return tcbInfoMeasurements;
    }

    private Stream<? extends X509CRLEntry> getCrlEntriesWithoutTcbInfoExtension(X509CRL crl) {
        return getX509CRLEntries(crl)
            .filter(entry -> !containsTcbInfoExtension(entry));
    }

    private Stream<? extends X509CRLEntry> getCrlEntriesWithTcbInfoExtension(X509CRL crl) {
        return getX509CRLEntries(crl)
            .filter(X509CRLEntry::hasExtensions)
            .filter(TcbInfoExtensionParser::containsTcbInfoExtension);
    }

    private void logFoundSubset(List<TcbInfoMeasurement> measurementsFromCertificate,
                                List<TcbInfoMeasurement> subsetOfMeasurementsFromCertificate) {
        log.debug("Found subset of TcbInfo measurements from certificate in CRL entry.\n"
                + "Measurements from certificate: {}\n"
                + "Measurements from CRL entry: {}",
            measurementsToString(measurementsFromCertificate),
            measurementsToString(subsetOfMeasurementsFromCertificate));
    }

    private String measurementsToString(List<TcbInfoMeasurement> measurements) {
        return String.join(",\n", measurements.stream().map(TcbInfoMeasurement::toString).toList());
    }
}
