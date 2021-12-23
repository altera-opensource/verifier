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
import com.intel.bkp.verifier.exceptions.SigmaException;
import com.intel.bkp.verifier.model.TrustedRootHash;
import com.intel.bkp.verifier.x509.X509CertificateChainVerifier;
import com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.LinkedList;

import static com.intel.bkp.ext.utils.HexConverter.toHex;
import static com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier.KEY_PURPOSE_CODE_SIGNING;

@Slf4j
@Getter(AccessLevel.PACKAGE)
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class S10ChainVerifier {

    private final X509CertificateChainVerifier certificateChainVerifier;
    private final X509CertificateExtendedKeyUsageVerifier extendedKeyUsageVerifier;
    private final CrlVerifier crlVerifier;
    private final RootHashVerifier rootHashVerifier;
    private final TrustedRootHash trustedRootHash;

    @Setter
    private byte[] deviceId;

    public S10ChainVerifier(ICrlProvider crlProvider, TrustedRootHash trustedRootHash) {
        this(new X509CertificateChainVerifier(), new X509CertificateExtendedKeyUsageVerifier(),
            new CrlVerifier(crlProvider), new RootHashVerifier(), trustedRootHash);
    }

    public void verifyChain(LinkedList<X509Certificate> certificates) {
        final var attCert = certificates.getFirst();
        final var rootCert = certificates.getLast();

        if (attCert.getSerialNumber().compareTo(CrlSerialNumberBuilder.convertToBigInteger(deviceId)) != 0) {
            handleVerificationFailure("Certificate Serial Number does not match device id.");
        }

        if (!certificateChainVerifier.certificates(certificates).verify()) {
            handleVerificationFailure("Parent signature verification in X509 attestation chain failed.");
        }

        if (!extendedKeyUsageVerifier.certificate(attCert).verify(KEY_PURPOSE_CODE_SIGNING)) {
            handleVerificationFailure("Attestation certificate is invalid.");
        }

        if (!rootHashVerifier.verifyRootHash(rootCert, trustedRootHash.getS10())) {
            handleVerificationFailure("Root hash in X509 attestation chain is different from trusted root hash.");
        }

        if (!crlVerifier.certificates(certificates).verify()) {
            handleVerificationFailure(String.format("Device with device id %s is revoked.", toHex(deviceId)));
        }
    }

    protected void handleVerificationFailure(String failureDetails) {
        throw new SigmaException(failureDetails);
    }
}
