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

import com.intel.bkp.core.properties.DistributionPoint;
import com.intel.bkp.fpgacerts.url.DistributionPointAddressProvider;
import com.intel.bkp.verifier.dp.DistributionPointChainFetcher;
import com.intel.bkp.verifier.dp.DistributionPointConnector;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.LinkedList;

import static com.intel.bkp.verifier.x509.X509UtilsWrapper.getIssuerCertUrl;

@Slf4j
@Getter(AccessLevel.PACKAGE)
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class DiceAttestationRevocationService {

    private final DistributionPointChainFetcher chainFetcher;
    private final DiceAliasChainVerifier diceAliasChainVerifier;
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
        this(new DistributionPointChainFetcher(new DistributionPointConnector(dp.getProxy())),
            new DiceAliasChainVerifier(
                new DistributionPointCrlProvider(dp.getProxy()), dp.getTrustedRootHash().getDice()),
            new DistributionPointAddressProvider(dp.getPathCer()));
    }

    public DiceAttestationRevocationService withDeviceId(byte[] deviceId) {
        diceAliasChainVerifier.setDeviceId(deviceId);
        return this;
    }

    public void add(X509Certificate x509Certificate) {
        certificates.add(x509Certificate);
    }

    public void addIid(X509Certificate x509Certificate) {
        certificatesIID.add(x509Certificate);
    }

    public void verifyChains() {
        preVerifyChain();
        fetchParents();
        verifyChainsInternal();
    }

    private void preVerifyChain() {
        if (!certificatesIID.isEmpty()) {
            log.debug("Comparing AuthorityInformationAccess of Alias chain and IID Alias chain.");
            compareAuthorityInfoAccess();
        }
    }

    private void fetchParents() {
        final var parents = chainFetcher.downloadCertificateChain(getIssuerCertUrl(certificates.getLast()));
        certificates.addAll(parents);
        if (!certificatesIID.isEmpty()) {
            certificatesIID.addAll(parents);
        }
    }

    private void verifyChainsInternal() {
        log.debug("Verifying chain with EFUSE UDS that has {} certificates.", certificates.size());
        diceAliasChainVerifier.verifyChainWitchTcbInfoValidation(certificates);

        if (!certificatesIID.isEmpty()) {
            log.debug("Verifying chain with IID UDS that has {} certificates.", certificatesIID.size());
            diceAliasChainVerifier.verifyChain(certificatesIID);
        }
    }

    private void compareAuthorityInfoAccess() {
        final String pathToIssuer = getIssuerCertUrl(certificates.getLast());
        final String pathToIssuerIid = getIssuerCertUrl(certificatesIID.getLast());

        if (!pathToIssuer.equals(pathToIssuerIid)) {
            throw new InternalLibraryException(
                    "AuthorityInformationAccess from Alias chain and IID Alias chain do not match.");
        }
    }
}
