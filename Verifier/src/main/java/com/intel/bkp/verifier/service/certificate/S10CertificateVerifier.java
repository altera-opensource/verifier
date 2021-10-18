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

import com.intel.bkp.ext.core.crl.CrlSerialNumberBuilder;
import com.intel.bkp.ext.utils.HexConverter;
import com.intel.bkp.verifier.dp.DistributionPointConnector;
import com.intel.bkp.verifier.dp.ProxyCallbackFactory;
import com.intel.bkp.verifier.exceptions.SigmaException;
import com.intel.bkp.verifier.model.IpcsDistributionPoint;
import com.intel.bkp.verifier.model.s10.S10Params;
import com.intel.bkp.verifier.x509.X509CertificateChainVerifier;
import com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import static com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier.KEY_PURPOSE_CODE_SIGNING;

@Slf4j
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class S10CertificateVerifier {

    private DistributionPointConnector connector = new DistributionPointConnector();
    private X509CertificateParser certificateParser = new X509CertificateParser();
    private X509CertificateChainVerifier certificateChainVerifier = new X509CertificateChainVerifier();
    private X509CertificateExtendedKeyUsageVerifier extendedKeyUsageVerifier =
        new X509CertificateExtendedKeyUsageVerifier();
    private CrlVerifier crlVerifier = new CrlVerifier();
    private ProxyCallbackFactory proxyCallbackFactory = new ProxyCallbackFactory();
    private DistributionPointAddressProvider addressProvider = new DistributionPointAddressProvider();
    private RootHashVerifier rootHashVerifier = new RootHashVerifier();

    private X509Certificate attestationCert;
    private X509Certificate ipcsSigningCertificate;
    private X509Certificate rootCertificate;
    private IpcsDistributionPoint dp;

    private final LinkedList<X509Certificate> certificates = new LinkedList<>();

    public void withDistributionPoint(IpcsDistributionPoint dp) {
        this.dp = dp;
        addressProvider.withDistributionPoint(dp);
        crlVerifier.withDistributionPoint(dp);
        connector.setProxy(proxyCallbackFactory.get(dp.getProxyHost(), dp.getProxyPort()));
    }

    public void verify(byte[] deviceId, String pufTypeHex) {
        log.debug("Building PufAttestation certificate chain.");
        attestationCert = getAttestationCertificate(S10Params.from(deviceId, pufTypeHex));
        certificates.add(attestationCert);
        final String pathToIssuerCertificate = certificateParser.getPathToIssuerCertificateLocation(attestationCert);

        ipcsSigningCertificate = getIpcsSigningCertificate(pathToIssuerCertificate);
        certificates.add(ipcsSigningCertificate);
        final String pathToRootCertificate =
            certificateParser.getPathToIssuerCertificateLocation(ipcsSigningCertificate);

        rootCertificate = getRootCertificate(pathToRootCertificate);
        certificates.add(rootCertificate);

        if (attestationCert.getSerialNumber().compareTo(CrlSerialNumberBuilder.convertToBigInteger(deviceId)) != 0) {
            throw new SigmaException("Certificate Serial Number does not match device id.");
        }

        if (!certificateChainVerifier.certificates(certificates).verify()) {
            throw new SigmaException("Parent signature verification in X509 attestation chain failed.");
        }

        if (!extendedKeyUsageVerifier.certificate(attestationCert).verify(KEY_PURPOSE_CODE_SIGNING)) {
            throw new SigmaException("Attestation certificate is invalid.");
        }

        if (!rootHashVerifier.verifyRootHash(rootCertificate, dp.getTrustedRootHash().getS10())) {
            throw new SigmaException("Root hash in X509 attestation chain is different from trusted root hash.");
        }

        if (!crlVerifier.certificates(certificates).verify()) {
            throw new SigmaException(String.format("Device with device id %s is revoked.",
                HexConverter.toHex(deviceId)));
        }
    }

    public PublicKey getAttestationPublicKey() {
        return attestationCert.getPublicKey();
    }

    private X509Certificate getAttestationCertificate(S10Params s10Params) {
        return certificateParser.toX509(connector.getBytes(addressProvider.getAttestationCertFilename(s10Params)));
    }

    private X509Certificate getIpcsSigningCertificate(String ipcsCertificateUrl) {
        return certificateParser.toX509(connector.getBytes(ipcsCertificateUrl));
    }

    private X509Certificate getRootCertificate(String rootCertificateUrl) {
        return certificateParser.toX509(connector.getString(rootCertificateUrl));
    }
}
