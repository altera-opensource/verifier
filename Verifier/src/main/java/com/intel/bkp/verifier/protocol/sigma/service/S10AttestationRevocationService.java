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

package com.intel.bkp.verifier.protocol.sigma.service;

import com.intel.bkp.fpgacerts.dp.DistributionPointChainFetcher;
import com.intel.bkp.fpgacerts.dp.DistributionPointCrlProvider;
import com.intel.bkp.fpgacerts.url.DistributionPointAddressProvider;
import com.intel.bkp.fpgacerts.url.params.S10Params;
import com.intel.bkp.verifier.service.certificate.AppContext;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

@Slf4j
@Getter(AccessLevel.PACKAGE)
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class S10AttestationRevocationService {

    private final S10ChainVerifier s10ChainVerifier;
    private final DistributionPointChainFetcher chainFetcher;
    private final DistributionPointAddressProvider addressProvider;

    private final LinkedList<X509Certificate> certificates = new LinkedList<>();

    public S10AttestationRevocationService() {
        this(AppContext.instance());
    }

    public S10AttestationRevocationService(AppContext appContext) {
        this(new S10ChainVerifier(new DistributionPointCrlProvider(appContext.getDpConnector()),
                appContext.getDpTrustedRootHashes()),
            new DistributionPointChainFetcher(appContext.getDpConnector()),
            new DistributionPointAddressProvider(appContext.getDpPathCer()));
    }

    public PublicKey checkAndRetrieve(byte[] deviceId, String pufTypeHex) {
        certificates.clear();
        certificates.addAll(fetchChain(deviceId, pufTypeHex));

        s10ChainVerifier.setDeviceId(deviceId);
        s10ChainVerifier.verifyChain(certificates);

        return getAttestationPublicKey();
    }

    public PublicKey getAttestationPublicKey() {
        final var attCert = certificates.getFirst();
        return attCert.getPublicKey();
    }

    private List<X509Certificate> fetchChain(byte[] deviceId, String pufTypeHex) {
        log.debug("Building PufAttestation certificate chain.");

        final var s10Params = S10Params.from(deviceId, pufTypeHex);
        final String attestationCertificateUrl = addressProvider.getAttestationCertUrl(s10Params);
        return chainFetcher.downloadCertificateChainAsX509(attestationCertificateUrl);
    }

}
