/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

import com.intel.bkp.ext.core.certificate.X509CertificateUtils;
import com.intel.bkp.verifier.dp.DistributionPointConnector;
import com.intel.bkp.verifier.dp.ProxyCallbackFactory;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import com.intel.bkp.verifier.model.IpcsDistributionPoint;
import com.intel.bkp.verifier.model.dice.DiceEnrollmentParams;
import com.intel.bkp.verifier.model.dice.DiceParams;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.Optional;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@NoArgsConstructor
public class DiceAttestationRevocationService {

    private DistributionPointConnector connector = new DistributionPointConnector();
    private ProxyCallbackFactory proxyCallbackFactory = new ProxyCallbackFactory();
    private DiceCertificateVerifier diceCertificateVerifier = new DiceCertificateVerifier();
    private X509CertificateParser certificateParser = new X509CertificateParser();
    private DistributionPointAddressProvider addressProvider = new DistributionPointAddressProvider();

    private final LinkedList<X509Certificate> certificates = new LinkedList<>();
    private final LinkedList<X509Certificate> certificatesIID = new LinkedList<>();

    public void withDistributionPoint(IpcsDistributionPoint dp) {
        diceCertificateVerifier.withDistributionPoint(dp);
        addressProvider.withDistributionPoint(dp);
        connector.setProxy(proxyCallbackFactory.get(dp.getProxyHost(), dp.getProxyPort()));
    }

    public void withDeviceId(byte[] deviceId) {
        diceCertificateVerifier.withDeviceId(deviceId);
    }

    public void add(X509Certificate x509Certificate) {
        certificates.add(x509Certificate);
    }

    public void addIid(X509Certificate x509Certificate) {
        certificatesIID.add(x509Certificate);
    }

    public Optional<X509Certificate> fmGetDeviceIdCert(DiceParams diceParams) {
        return connector.tryGetBytes(addressProvider.getDeviceIdCertFilename(diceParams))
            .map(certificateParser::toX509);
    }

    public Optional<X509Certificate> fmGetEnrollmentCert(DiceParams diceParams,
        DiceEnrollmentParams diceEnrollmentParams) {
        return connector.tryGetBytes(addressProvider.getEnrollmentCertFilename(diceParams, diceEnrollmentParams))
            .map(certificateParser::toX509);
    }

    public Optional<X509Certificate> fmGetIidUdsCert(DiceParams diceParams) {
        return connector.tryGetBytes(addressProvider.getIidUdsCertFilename(diceParams))
            .map(certificateParser::toX509);
    }

    public Optional<X509Certificate> fmGetParent(String pathToIssuer) {
        return connector.tryGetBytes(pathToIssuer)
            .map(certificateParser::toX509);
    }

    public void verifyChains() {
        if (certificatesIID.size() != 0) {
            log.debug("Comparing AuthorityInformationAccess of Alias chain and IID Alias chain.");
            compareAuthorityInfoAccess();
        }

        getParent(certificates.getLast());

        while (!X509CertificateUtils.isSelfSigned(certificates.getLast())) {
            log.debug("Not self-signed cert, moving on: {}", certificates.getLast().getSubjectDN());
            getParent(certificates.getLast());
        }

        verifyChainsInternal();
    }

    private void verifyChainsInternal() {
        log.debug("Verifying chain with EFUSE UDS that has {} certificates.", certificates.size());
        diceCertificateVerifier.verify(certificates);

        if (!certificatesIID.isEmpty()) {
            log.debug("Verifying chain with IID UDS that has {} certificates.", certificatesIID.size());
            diceCertificateVerifier.verify(certificatesIID);
        }
    }

    private void getParent(X509Certificate child) {
        final String nextPathToIssuer = certificateParser.getPathToIssuerCertificateLocation(child);
        final Optional<X509Certificate> nextParentCert = fmGetParent(nextPathToIssuer);

        nextParentCert.ifPresentOrElse(this::addParentToChains,
            () -> {
                throw new InternalLibraryException("Parent certificate not found on Distribution Point.");
            }
        );
    }

    private void addParentToChains(X509Certificate x509Certificate) {
        certificates.add(x509Certificate);
        if (certificatesIID.size() != 0) {
            certificatesIID.add(x509Certificate);
        }
    }

    private void compareAuthorityInfoAccess() {
        final String pathToIssuer = certificateParser.getPathToIssuerCertificateLocation(certificates.getLast());
        final String pathToIssuerIid = certificateParser.getPathToIssuerCertificateLocation(certificatesIID.getLast());

        if (!pathToIssuer.equals(pathToIssuerIid)) {
            throw new InternalLibraryException(
                "AuthorityInformationAccess from Alias chain and IID Alias chain do not match.");
        }
    }
}
