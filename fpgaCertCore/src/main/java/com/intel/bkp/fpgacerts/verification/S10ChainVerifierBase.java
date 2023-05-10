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

package com.intel.bkp.fpgacerts.verification;

import com.intel.bkp.crypto.x509.validation.ChainVerifier;
import com.intel.bkp.crypto.x509.validation.ExtendedKeyUsageVerifier;
import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.List;

import static com.intel.bkp.crypto.x509.validation.ExtendedKeyUsageVerifier.KEY_PURPOSE_CODE_SIGNING;
import static com.intel.bkp.fpgacerts.utils.DeviceIdUtils.getS10CertificateSerialNumber;
import static com.intel.bkp.utils.ListUtils.toLinkedList;

@Slf4j
@Getter
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public abstract class S10ChainVerifierBase {

    private final ChainVerifier chainVerifier;
    private final ExtendedKeyUsageVerifier extendedKeyUsageVerifier;
    private final CrlVerifier crlVerifier;
    private final RootHashVerifier rootHashVerifier;
    private final String trustedRootHash;

    @Setter
    private byte[] deviceId;

    public S10ChainVerifierBase(ICrlProvider crlProvider, String trustedRootHash) {
        this(new ChainVerifier(), new ExtendedKeyUsageVerifier(),
                new CrlVerifier(crlProvider), new RootHashVerifier(), trustedRootHash);
    }

    protected abstract void handleVerificationFailure(String failureDetails);

    public void verifyChain(List<X509Certificate> certs) {
        final var certificates = toLinkedList(certs);
        final var attCert = certificates.getFirst();
        final var rootCert = certificates.getLast();

        if (attCert.getSerialNumber().compareTo(getS10CertificateSerialNumber(deviceId)) != 0) {
            handleVerificationFailure("Certificate Serial Number does not match device id.");
        }

        if (!chainVerifier.certificates(certificates).verify()) {
            handleVerificationFailure("Parent signature verification in X509 attestation chain failed.");
        }

        if (!extendedKeyUsageVerifier.certificate(attCert).verify(KEY_PURPOSE_CODE_SIGNING)) {
            handleVerificationFailure("Attestation certificate is invalid.");
        }

        if (!rootHashVerifier.verifyRootHash(rootCert, trustedRootHash)) {
            handleVerificationFailure("Root hash in X509 attestation chain is different from trusted root hash.");
        }

        if (!crlVerifier.certificates(certificates).verify()) {
            handleVerificationFailure("One of the certificates in chain is revoked.");
        }
    }
}
