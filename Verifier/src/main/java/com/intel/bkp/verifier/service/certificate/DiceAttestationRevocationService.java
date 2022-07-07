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

import com.intel.bkp.fpgacerts.url.DistributionPointAddressProvider;
import com.intel.bkp.verifier.dp.DistributionPointChainFetcher;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import static com.intel.bkp.verifier.x509.X509UtilsWrapper.getIssuerCertUrl;

@Slf4j
@Getter(AccessLevel.PACKAGE)
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class DiceAttestationRevocationService {

    private final DistributionPointChainFetcher chainFetcher;
    private final DiceAliasChainVerifier diceAliasChainVerifier;
    private final DistributionPointAddressProvider addressProvider;

    public DiceAttestationRevocationService() {
        this(AppContext.instance());
    }

    public DiceAttestationRevocationService(AppContext appContext) {
        this(new DistributionPointChainFetcher(appContext.getDpConnector()),
            new DiceAliasChainVerifier(new DistributionPointCrlProvider(appContext),
                appContext.getDpTrustedRootHash().getDice()),
            new DistributionPointAddressProvider(appContext.getDpPathCer()));
    }

    public void verifyChains(byte[] deviceId, List<X509Certificate> efuseChain, List<X509Certificate> iidChain) {
        verifyChains(deviceId, new LinkedList<>(efuseChain), new LinkedList<>(iidChain));
    }

    public void verifyChains(byte[] deviceId, LinkedList<X509Certificate> efuseChain,
                             LinkedList<X509Certificate> iidChain) {
        preVerifyChain(efuseChain, iidChain);
        fetchParents(efuseChain, iidChain);
        verifyChainsInternal(deviceId, efuseChain, iidChain);
    }

    private void preVerifyChain(LinkedList<X509Certificate> efuseChain, LinkedList<X509Certificate> iidChain) {
        if (!iidChain.isEmpty()) {
            log.debug("Comparing AuthorityInformationAccess of Alias chain and IID Alias chain.");
            compareAuthorityInfoAccess(efuseChain, iidChain);
        }
    }

    private void fetchParents(LinkedList<X509Certificate> efuseChain, LinkedList<X509Certificate> iidChain) {
        final var parents = chainFetcher.downloadCertificateChain(getIssuerCertUrl(efuseChain.getLast()));
        efuseChain.addAll(parents);
        if (!iidChain.isEmpty()) {
            iidChain.addAll(parents);
        }
    }

    private void verifyChainsInternal(byte[] deviceId,
                                      LinkedList<X509Certificate> efuseChain,
                                      LinkedList<X509Certificate> iidChain) {
        diceAliasChainVerifier.setDeviceId(deviceId);

        log.debug("Verifying chain with EFUSE UDS that has {} certificates.", efuseChain.size());
        diceAliasChainVerifier.verifyChainWitchTcbInfoValidation(efuseChain);

        if (!iidChain.isEmpty()) {
            log.debug("Verifying chain with IID UDS that has {} certificates.", iidChain.size());
            diceAliasChainVerifier.verifyChain(iidChain);
        }
    }

    private void compareAuthorityInfoAccess(LinkedList<X509Certificate> efuseChain,
                                            LinkedList<X509Certificate> iidChain) {
        final String pathToIssuer = getIssuerCertUrl(efuseChain.getLast());
        final String pathToIssuerIid = getIssuerCertUrl(iidChain.getLast());

        if (!pathToIssuer.equals(pathToIssuerIid)) {
            throw new InternalLibraryException(
                "AuthorityInformationAccess from Alias chain and IID Alias chain do not match.");
        }
    }
}
