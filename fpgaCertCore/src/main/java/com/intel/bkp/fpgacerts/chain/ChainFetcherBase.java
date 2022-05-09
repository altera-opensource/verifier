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

package com.intel.bkp.fpgacerts.chain;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.utils.AuthorityInformationAccessUtils.getIssuerCertUrl;
import static com.intel.bkp.crypto.x509.utils.X509CertificateUtils.isSelfSigned;

@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class ChainFetcherBase {

    protected final ICertificateFetcher certificateFetcher;

    protected abstract RuntimeException getFetchingFailureException(String url);

    protected abstract RuntimeException getNoIssuerCertUrlException(String certificateSubject);

    protected List<DistributionPointCertificate> fetchCertificateChain(String url) {
        final var certChain = new LinkedList<DistributionPointCertificate>();
        if (StringUtils.isNotBlank(url)) {
            fetchCertificateChainRecursive(url, certChain);
        }
        return certChain;
    }

    protected List<DistributionPointCertificate> fetchCertificateChain(X509Certificate cert) {
        final var certChain = new LinkedList<DistributionPointCertificate>();
        Optional.ofNullable(cert).ifPresent(c -> fetchCertificateChainRecursive(c, certChain));
        return certChain;
    }

    private void fetchCertificateChainRecursive(String url, List<DistributionPointCertificate> certChain) {
        final X509Certificate currentCert = certificateFetcher.fetchCertificate(url)
            .orElseThrow(() -> getFetchingFailureException(url));

        certChain.add(new DistributionPointCertificate(url, currentCert));

        if (isSelfSigned(currentCert)) {
            return;
        }

        fetchCertificateChainRecursive(currentCert, certChain);
    }

    private void fetchCertificateChainRecursive(X509Certificate cert,
                                                List<DistributionPointCertificate> certChain) {
        getIssuerCertUrl(cert)
            .ifPresentOrElse(issuerUrl -> fetchCertificateChainRecursive(issuerUrl, certChain),
                handleNoIssuerCertUrl(cert));
    }

    private Runnable handleNoIssuerCertUrl(X509Certificate currentCert) {
        return () -> {
            throw getNoIssuerCertUrlException(currentCert.getSubjectDN().getName());
        };
    }
}
