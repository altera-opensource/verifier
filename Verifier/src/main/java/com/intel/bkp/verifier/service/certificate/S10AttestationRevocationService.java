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
import com.intel.bkp.verifier.model.DistributionPoint;
import com.intel.bkp.verifier.model.s10.S10Params;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

@Slf4j
@Getter(AccessLevel.PACKAGE)
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class S10AttestationRevocationService {

    private final X509CertificateParser certificateParser;
    private final S10ChainVerifier s10ChainVerifier;
    private final DistributionPointConnector connector;
    private final DistributionPointAddressProvider addressProvider;

    private final LinkedList<X509Certificate> certificates = new LinkedList<>();

    public S10AttestationRevocationService() {
        this(AppContext.instance());
    }

    public S10AttestationRevocationService(AppContext appContext) {
        this(appContext.getLibConfig().getDistributionPoint());
    }

    public S10AttestationRevocationService(DistributionPoint dp) {
        this(new X509CertificateParser(),
            new S10ChainVerifier(new DistributionPointCrlProvider(dp.getProxy()), dp.getTrustedRootHash()),
            new DistributionPointConnector(dp.getProxy()),
            new DistributionPointAddressProvider(dp.getPathCer()));
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

    private LinkedList<X509Certificate> fetchChain(byte[] deviceId, String pufTypeHex) {
        log.debug("Building PufAttestation certificate chain.");

        final var s10Params = S10Params.from(deviceId, pufTypeHex);
        final String attestationCertificatePath = addressProvider.getAttestationCertFilename(s10Params);
        final var attestationCert = downloadCertificate(attestationCertificatePath);

        final var certs = new LinkedList<X509Certificate>();
        certs.add(attestationCert);
        return fetchParents(certs);
    }

    private LinkedList<X509Certificate> fetchParents(LinkedList<X509Certificate> certs) {
        while (!X509CertificateUtils.isSelfSigned(certs.getLast())) {
            log.debug("Not self-signed cert, moving on: {}", certs.getLast().getSubjectDN());
            certs.add(getParent(certs.getLast()));
        }

        return certs;
    }

    private X509Certificate getParent(X509Certificate child) {
        final String parentPath = certificateParser.getPathToIssuerCertificate(child);
        return downloadCertificate(parentPath);
    }

    private X509Certificate downloadCertificate(String url) {
        return certificateParser.toX509(connector.getBytes(url));
    }
}
