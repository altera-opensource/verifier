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
import com.intel.bkp.crypto.x509.validation.SubjectKeyIdentifierVerifier;
import com.intel.bkp.fpgacerts.dice.subject.DiceSubjectVerifier;
import com.intel.bkp.fpgacerts.dice.tcbinfo.verification.TcbInfoVerifier;
import com.intel.bkp.fpgacerts.dice.ueid.UeidVerifier;
import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_MULTI_TCB_INFO;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_TCB_INFO;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_UEID;
import static com.intel.bkp.utils.ListUtils.toLinkedList;

@Slf4j
@Getter
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public abstract class DiceChainVerifierBase {

    private static final Set<String> DICE_EXTENSION_OIDS = Set.of(TCG_DICE_TCB_INFO.getOid(),
        TCG_DICE_MULTI_TCB_INFO.getOid(), TCG_DICE_UEID.getOid());

    private final ExtendedKeyUsageVerifier extendedKeyUsageVerifier;
    private final ChainVerifier certificateChainVerifier;
    private final DiceCrlVerifier crlVerifier;
    private final RootHashVerifier rootHashVerifier;
    private final UeidVerifier ueidVerifier;
    private final SubjectKeyIdentifierVerifier subjectKeyIdentifierVerifier;
    private final String trustedRootHash;
    private final TcbInfoVerifier tcbInfoVerifier;
    private final DiceSubjectVerifier diceSubjectVerifier;

    @Setter
    private byte[] deviceId;

    protected DiceChainVerifierBase(ICrlProvider crlProvider, String trustedRootHash, boolean testModeSecrets) {
        this(new ExtendedKeyUsageVerifier(), new ChainVerifier(), new DiceCrlVerifier(crlProvider),
            new RootHashVerifier(),
            new UeidVerifier(), new SubjectKeyIdentifierVerifier(), trustedRootHash,
            new TcbInfoVerifier(testModeSecrets), new DiceSubjectVerifier());
    }

    protected abstract String[] getExpectedLeafCertKeyPurposes();

    protected abstract void handleVerificationFailure(String failureDetails);

    public void verifyChain(List<X509Certificate> certificates) {
        verifyChainInternal(certificates);
        verifyTcbInfo(certificates);
    }

    private void verifyChainInternal(List<X509Certificate> certs) {
        log.info("Performing standard X509 validation of certificate chain.");
        final var certificates = toLinkedList(certs);
        if (!certificateChainVerifier.certificates(certificates)
            .knownExtensionOids(DICE_EXTENSION_OIDS).verify()) {
            handleVerificationFailure("Parent signature verification in X509 attestation chain failed.");
        }

        if (!ueidVerifier.certificates(certificates).verify(deviceId)) {
            handleVerificationFailure(
                "One of certificates in X509 attestation chain has invalid UEID extension value.");
        }

        if (!subjectKeyIdentifierVerifier.certificates(certificates).verify()) {
            handleVerificationFailure("One of certificates in X509 attestation chain has invalid SKI extension value.");
        }

        if (!rootHashVerifier.verifyRootHash(certificates.getLast(), trustedRootHash)) {
            handleVerificationFailure("Root hash in X509 DICE chain is different from trusted root hash.");
        }

        if (!extendedKeyUsageVerifier.certificate(certificates.getFirst()).verify(getExpectedLeafCertKeyPurposes())) {
            handleVerificationFailure("Leaf certificate has invalid key usages.");
        }

        if (!diceSubjectVerifier.certificates(certificates).verify()) {
            handleVerificationFailure("DICE subject validation failed.");
        }

        if (!crlVerifier.certificates(certificates).doNotRequireCrlForLeafCertificate().verify()) {
            handleVerificationFailure("One of the certificates in chain is revoked.");
        }
    }

    private void verifyTcbInfo(List<X509Certificate> certificates) {
        log.info("Performing DICE validation of certificate chain.");
        if (!tcbInfoVerifier.certificates(certificates).verify()) {
            handleVerificationFailure("TcbInfo validation failed.");
        }
    }
}
