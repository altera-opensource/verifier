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
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import com.intel.bkp.verifier.model.DistributionPoint;
import com.intel.bkp.verifier.model.dice.DiceEnrollmentParams;
import com.intel.bkp.verifier.model.dice.DiceParams;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.Optional;

@Slf4j
@Getter(AccessLevel.PACKAGE)
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class DiceAttestationRevocationService {

    private final DistributionPointConnector connector;
    private final DiceCertificateVerifier diceCertificateVerifier;
    private final X509CertificateParser certificateParser;
    private final DistributionPointAddressProvider addressProvider;

    private final LinkedList<X509Certificate> certificates = new LinkedList<>();
    private final LinkedList<X509Certificate> certificatesIID = new LinkedList<>();

    public DiceAttestationRevocationService() {
        this(AppContext.instance());
    }

    public DiceAttestationRevocationService(AppContext appContext) {
        this(appContext.getLibConfig().getDistributionPoint());
    }

    public DiceAttestationRevocationService(DistributionPoint dp) {
        this(new DistributionPointConnector(dp.getProxy()),
            new DiceCertificateVerifier(new DistributionPointCrlProvider(dp.getProxy()), dp.getTrustedRootHash()),
            new X509CertificateParser(),
            new DistributionPointAddressProvider(dp.getPathCer()));
    }

    public DiceAttestationRevocationService withDeviceId(byte[] deviceId) {
        diceCertificateVerifier.withDeviceId(deviceId);
        return this;
    }

    public void add(X509Certificate x509Certificate) {
        certificates.add(x509Certificate);
    }

    public void addIid(X509Certificate x509Certificate) {
        certificatesIID.add(x509Certificate);
    }

    public Optional<X509Certificate> fmGetDeviceIdCert(DiceParams diceParams) {
        final String url = addressProvider.getDeviceIdCertFilename(diceParams);
        return getContent(url);
    }

    public Optional<X509Certificate> fmGetEnrollmentCert(DiceEnrollmentParams diceEnrollmentParams) {
        final String url = addressProvider.getEnrollmentCertFilename(diceEnrollmentParams);
        return getContent(url);
    }

    public Optional<X509Certificate> fmGetIidUdsCert(DiceParams diceParams) {
        final String url = addressProvider.getIidUdsCertFilename(diceParams);
        return getContent(url);
    }

    public Optional<X509Certificate> getContent(String url) {
        return connector.tryGetBytes(url)
            .map(certificateParser::toX509);
    }

    public void verifyChains() {
        preVerifyChain();
        fetchParents();
        verifyChainsInternal();
    }

    private void preVerifyChain() {
        if (certificatesIID.size() != 0) {
            log.debug("Comparing AuthorityInformationAccess of Alias chain and IID Alias chain.");
            compareAuthorityInfoAccess();
        }
    }

    private void fetchParents() {
        getParent(certificates.getLast());

        while (!X509CertificateUtils.isSelfSigned(certificates.getLast())) {
            log.debug("Not self-signed cert, moving on: {}", certificates.getLast().getSubjectDN());
            getParent(certificates.getLast());
        }
    }

    private void verifyChainsInternal() {
        log.debug("Verifying chain with EFUSE UDS that has {} certificates.", certificates.size());
        diceCertificateVerifier.verifyAliasChain(certificates);

        if (!certificatesIID.isEmpty()) {
            log.debug("Verifying chain with IID UDS that has {} certificates.", certificatesIID.size());
            diceCertificateVerifier.verifyAliasChain(certificatesIID);
        }
    }

    private void getParent(X509Certificate child) {
        final String nextPathToIssuer = certificateParser.getPathToIssuerCertificate(child);
        final Optional<X509Certificate> nextParentCert = getContent(nextPathToIssuer);

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
        final String pathToIssuer = certificateParser.getPathToIssuerCertificate(certificates.getLast());
        final String pathToIssuerIid = certificateParser.getPathToIssuerCertificate(certificatesIID.getLast());

        if (!pathToIssuer.equals(pathToIssuerIid)) {
            throw new InternalLibraryException(
                "AuthorityInformationAccess from Alias chain and IID Alias chain do not match.");
        }
    }
}
