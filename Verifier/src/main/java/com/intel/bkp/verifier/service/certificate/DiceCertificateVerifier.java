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

import com.intel.bkp.verifier.exceptions.SigmaException;
import com.intel.bkp.verifier.model.TrustedRootHash;
import com.intel.bkp.verifier.x509.X509CertificateChainVerifier;
import com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier;
import com.intel.bkp.verifier.x509.X509CertificateSubjectKeyIdentifierVerifier;
import com.intel.bkp.verifier.x509.X509CertificateUeidVerifier;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.Set;

import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_MULTI_TCB_INFO;
import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_TCB_INFO;
import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_UEID;
import static com.intel.bkp.verifier.x509.X509CertificateBasicConstraintsVerifier.CA_TRUE_PATHLENGTH_NONE;
import static com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier.KEY_PURPOSE_ATTEST_INIT;
import static com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier.KEY_PURPOSE_ATTEST_LOC;

@Slf4j
@Getter(AccessLevel.PACKAGE)
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class DiceCertificateVerifier {

    private static final int ROOT_BASIC_CONSTRAINTS = CA_TRUE_PATHLENGTH_NONE;
    private static final Set<String> DICE_EXTENSION_OIDS = Set.of(TCG_DICE_TCB_INFO.getOid(),
        TCG_DICE_MULTI_TCB_INFO.getOid(), TCG_DICE_UEID.getOid());

    protected final X509CertificateExtendedKeyUsageVerifier extendedKeyUsageVerifier;
    private final X509CertificateChainVerifier certificateChainVerifier;
    private final CrlVerifier crlVerifier;
    private final RootHashVerifier rootHashVerifier;
    private final X509CertificateUeidVerifier ueidVerifier;
    private final X509CertificateSubjectKeyIdentifierVerifier subjectKeyIdentifierVerifier;
    private final TrustedRootHash trustedRootHash;

    private byte[] deviceId;

    public DiceCertificateVerifier(ICrlProvider crlProvider, TrustedRootHash trustedRootHash) {
        this(new X509CertificateExtendedKeyUsageVerifier(), new X509CertificateChainVerifier(),
            new CrlVerifier(crlProvider), new RootHashVerifier(), new X509CertificateUeidVerifier(),
            new X509CertificateSubjectKeyIdentifierVerifier(), trustedRootHash);
    }

    public DiceCertificateVerifier withDeviceId(byte[] deviceId) {
        this.deviceId = deviceId;
        return this;
    }

    public void verifyAliasChain(LinkedList<X509Certificate> certificates) {
        verifyCommon(certificates);

        if (!extendedKeyUsageVerifier.certificate(certificates.getFirst())
            .verify(KEY_PURPOSE_ATTEST_INIT, KEY_PURPOSE_ATTEST_LOC)) {
            throw new SigmaException("Alias certificate is invalid.");
        }
    }

    protected void verifyCommon(LinkedList<X509Certificate> certificates) {
        if (!certificateChainVerifier.certificates(certificates).rootBasicConstraints(ROOT_BASIC_CONSTRAINTS)
            .knownExtensionOids(DICE_EXTENSION_OIDS).verify()) {
            throw new SigmaException("Parent signature verification in X509 attestation chain failed.");
        }

        if (!ueidVerifier.certificates(certificates).verify(deviceId)) {
            throw new SigmaException("One of certificates in X509 attestation chain has invalid UEID extension value.");
        }

        if (!subjectKeyIdentifierVerifier.certificates(certificates).verify()) {
            throw new SigmaException("One of certificates in X509 attestation chain has invalid SKI extension value.");
        }

        if (!rootHashVerifier.verifyRootHash(certificates.getLast(), trustedRootHash.getDice())) {
            throw new SigmaException("Root hash in X509 DICE chain is different from trusted root hash.");
        }

        if (!crlVerifier.certificates(certificates).doNotRequireCrlForLeafCertificate().verify()) {
            throw new SigmaException("One of the certificates in chain is revoked.");
        }
    }
}
