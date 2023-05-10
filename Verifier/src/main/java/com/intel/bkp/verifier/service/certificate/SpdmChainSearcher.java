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

package com.intel.bkp.verifier.service.certificate;

import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import com.intel.bkp.crypto.x509.utils.X509CertificateUtils;
import com.intel.bkp.fpgacerts.verification.RootHashVerifier;
import com.intel.bkp.utils.ListUtils;
import com.intel.bkp.verifier.exceptions.SpdmCommandFailedException;
import com.intel.bkp.verifier.exceptions.ValidChainNotFoundException;
import com.intel.bkp.verifier.service.sender.SpdmGetCertificateMessageSender;
import com.intel.bkp.verifier.service.sender.SpdmGetDigestMessageSender;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509CertificateChain;
import static com.intel.bkp.crypto.x509.utils.X509CertificateUtils.makeRootLastCert;
import static com.intel.bkp.fpgacerts.dice.iidutils.IidUdsChainUtils.isIidUdsChain;
import static com.intel.bkp.verifier.service.certificate.DiceChainType.ATTESTATION;
import static com.intel.bkp.verifier.service.certificate.DiceChainType.IID;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class SpdmChainSearcher {

    private final SpdmGetDigestMessageSender spdmGetDigestMessageSender;
    private final SpdmGetCertificateMessageSender spdmGetCertificateMessageSender;
    private final SpdmChainPolicyProvider spdmChainPolicyProvider;
    private final SpdmDiceAttestationRevocationService diceAttestationRevocationService;
    private final RootHashVerifier rootHashVerifier;
    private final String trustedRootHash;
    private final ValidChainNotFoundHandler validChainNotFoundHandler;

    public SpdmChainSearcher() {
        this(AppContext.instance());
    }

    private SpdmChainSearcher(AppContext appContext) {
        this(new SpdmGetDigestMessageSender(),
            new SpdmGetCertificateMessageSender(),
            new SpdmChainPolicyProvider(),
            new SpdmDiceAttestationRevocationService(),
            new RootHashVerifier(),
            appContext.getDpTrustedRootHash().getDice(),
            new ValidChainNotFoundHandler());
    }

    public SpdmValidChains searchValidChains(byte[] deviceId) {
        log.info("*** REQUESTING CERTIFICATE CHAINS ***");
        final List<Integer> filledSlots = getFilledSlots(deviceId);
        return searchInSlotsUntilPolicyMet(filledSlots, deviceId);
    }

    private List<Integer> getFilledSlots(byte[] deviceId) {
        try {
            final List<Integer> filledSlots = spdmGetDigestMessageSender.send();
            log.info("Filled slots: {}", filledSlots);
            return filledSlots;
        } catch (SpdmCommandFailedException e) {
            log.error("GET_DIGEST failed - no filled slots available.");
            log.debug("Stacktrace: ", e);

            validChainNotFoundHandler.run(deviceId);
            throw new ValidChainNotFoundException();
        }
    }

    private SpdmValidChains searchInSlotsUntilPolicyMet(List<Integer> filledSlots, byte[] deviceId) {
        final SpdmValidChains validChains = new SpdmValidChains(deviceId);

        filledSlots.stream()
            .takeWhile(slotId -> !isPolicyMet(validChains))
            .forEach(slotId -> searchInSlot(slotId, validChains));

        ensurePolicyMet(validChains);

        return validChains;
    }

    private boolean isPolicyMet(SpdmValidChains validChains) {
        final boolean policyMet = spdmChainPolicyProvider.isPolicyMet(validChains);
        log.debug(policyMet ? "Policy met." : "Policy not met.");
        return policyMet;
    }

    private void searchInSlot(int slotId, SpdmValidChains validChains) {
        try {
            final List<X509Certificate> fullChain = getFullDeviceChainUpToTrustedRoot(slotId);
            addChainIfValid(validChains, slotId, fullChain);
        } catch (Exception e) {
            log.warn("Failed to search for chain in slot {}. Exception occurred: {}", slotId, e.getMessage());
            log.debug("Stacktrace: ", e);
        }
    }

    private List<X509Certificate> getFullDeviceChainUpToTrustedRoot(int slotId) throws SpdmCommandFailedException {
        log.info("Requesting chain from slot {}.", slotId);

        final var trustedChain = Optional.ofNullable(spdmGetCertificateMessageSender.send(slotId))
            .filter(value -> value.length != 0)
            .map(this::tryParseCertificateChain)
            .filter(x509Certificates -> !x509Certificates.isEmpty())
            .filter(this::isRootTrusted)
            .orElse(List.of());

        log.info("Trusted chain {} in slot.", trustedChain.isEmpty() ? "not found" : "found");
        return trustedChain;
    }

    private List<X509Certificate> tryParseCertificateChain(byte[] certificateChain) {
        try {
            return makeRootLastCert(toX509CertificateChain(certificateChain));
        } catch (X509CertificateParsingException e) {
            log.warn("Failed to parse chain of certificates: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return List.of();
        }
    }

    private boolean isRootTrusted(List<X509Certificate> x509Certificates) {
        return Optional.ofNullable(x509Certificates)
            .map(ListUtils::toLinkedList)
            .map(LinkedList::getLast)
            .filter(X509CertificateUtils::isSelfSigned)
            .filter(this::isTrusted)
            .isPresent();
    }

    private boolean isTrusted(X509Certificate cert) {
        return rootHashVerifier.verifyRootHash(cert, trustedRootHash);
    }

    private void addChainIfValid(SpdmValidChains validChains, int slotId, List<X509Certificate> fullChain) {
        if (fullChain.isEmpty()) {
            return;
        }

        final DiceChainType chainType = isIidUdsChain(fullChain) ? IID : ATTESTATION;
        final var chainToValidate = new SpdmCertificateChainHolder(slotId, chainType, fullChain);

        if (equivalentChainNotYetValidated(validChains, chainToValidate)
            && isValidChain(validChains.getDeviceId(), chainToValidate)) {
            validChains.add(chainToValidate);
        }
    }

    private boolean equivalentChainNotYetValidated(SpdmValidChains validChains,
                                                   SpdmCertificateChainHolder chainToValidate) {
        return !spdmChainPolicyProvider.equivalentChainValidated(validChains, chainToValidate);
    }

    private boolean isValidChain(byte[] deviceId, SpdmCertificateChainHolder fullChain) {
        try {
            diceAttestationRevocationService.verifyChain(deviceId, fullChain);
            return true;
        } catch (Exception e) {
            log.warn("Failed to validate SPDM chain of certificates: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return false;
        }
    }

    private void ensurePolicyMet(SpdmValidChains validChains) {
        if (!isPolicyMet(validChains)) {
            validChainNotFoundHandler.run(validChains.getDeviceId());
            throw new ValidChainNotFoundException();
        }
    }
}
