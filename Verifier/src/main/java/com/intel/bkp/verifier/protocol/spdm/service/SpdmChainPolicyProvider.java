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

package com.intel.bkp.verifier.protocol.spdm.service;

import com.intel.bkp.fpgacerts.dice.iidutils.IidFlowDetector;
import com.intel.bkp.utils.ListUtils;
import com.intel.bkp.verifier.service.certificate.IidAliasFlowDetector;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.Optional;

import static com.intel.bkp.verifier.service.certificate.DiceChainType.ATTESTATION;
import static com.intel.bkp.verifier.service.certificate.DiceChainType.IID;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class SpdmChainPolicyProvider {

    private final IidFlowDetector iidFlowDetector;

    public SpdmChainPolicyProvider() {
        this(new IidAliasFlowDetector());
    }

    public boolean isPolicyMet(SpdmValidChains chains) {
        return attestationChainValidated(chains) && iidChainValidated(chains);
    }

    public boolean equivalentChainValidated(SpdmValidChains chains,
                                            SpdmCertificateChainHolder chainHolder) {
        final boolean result = switch (chainHolder.chainType()) {
            case ATTESTATION -> attestationChainValidated(chains);
            case IID -> iidChainValidated(chains);
        };

        log.debug("Equivalent {} chain {} validated.", chainHolder.chainType(), result ? "already" : "not yet");
        return result;
    }

    private boolean attestationChainValidated(SpdmValidChains chains) {
        return chains.contains(ATTESTATION);
    }

    private boolean iidChainValidated(SpdmValidChains chains) {
        return chains.contains(IID) || !isIidFlow(chains);
    }

    private boolean isIidFlow(SpdmValidChains chains) {
        return iidFlowDetector.isIidFlow(getLeafOfAttestationChain(chains));
    }

    private Optional<X509Certificate> getLeafOfAttestationChain(SpdmValidChains chains) {
        return Optional.ofNullable(chains.get(ATTESTATION))
            .map(SpdmCertificateChainHolder::chain)
            .filter(list -> !list.isEmpty())
            .map(ListUtils::toLinkedList)
            .map(LinkedList::getFirst);
    }
}
