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

package com.intel.bkp.fpgacerts.cbor.service;

import com.intel.bkp.fpgacerts.dp.DistributionPointChainFetcher;
import com.intel.bkp.fpgacerts.dp.DistributionPointConnector;
import com.intel.bkp.fpgacerts.dp.DistributionPointCrlProvider;
import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class RimSigningChainService {

    private final DistributionPointChainFetcher chainFetcher;
    private final RimSigningChainVerifier chainVerifier;

    public RimSigningChainService(DistributionPointConnector dpConnector, String[] trustedRootHash) {
        this(new DistributionPointChainFetcher(dpConnector),
            new DistributionPointCrlProvider(dpConnector),
            trustedRootHash
        );
    }

    public RimSigningChainService(DistributionPointChainFetcher chainFetcher, ICrlProvider crlProvider,
                                  String[] trustedRootHash) {
        this(chainFetcher, new RimSigningChainVerifier(crlProvider, trustedRootHash));
    }

    public PublicKey verifyRimSigningChainAndGetRimSigningKey(String signingCertUrl) {
        final var chain = fetchRimSigningChain(signingCertUrl);
        chainVerifier.verifyChain(chain);
        return chain.getFirst().getPublicKey();
    }


    private LinkedList<X509Certificate> fetchRimSigningChain(String url) {
        log.info("Fetching RIM Signing Certificate chain from: {}", url);
        final var chain = chainFetcher.downloadCertificateChainAsX509(url);
        return new LinkedList<>(chain);
    }
}
