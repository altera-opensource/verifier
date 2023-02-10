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

package com.intel.bkp.verifier.service.certificate;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.verifier.service.certificate.DiceChainType.ATTESTATION;
import static com.intel.bkp.verifier.service.certificate.DiceChainType.IID;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmChainPolicyProviderTest {

    private static final byte[] DEVICE_ID = new byte[]{1, 2};

    @Mock
    private X509Certificate attCert;

    @Mock
    private IidAliasFlowDetector iidFlowDetector;

    @InjectMocks
    private SpdmChainPolicyProvider sut;

    private SpdmCertificateChainHolder attChain;
    private SpdmCertificateChainHolder iidChain;
    private SpdmValidChains spdmValidChains;

    @BeforeEach
    void setUp() {
        spdmValidChains = new SpdmValidChains(DEVICE_ID);
        attChain = new SpdmCertificateChainHolder(1, ATTESTATION, List.of(attCert));
        iidChain = new SpdmCertificateChainHolder(2, IID, List.of());
    }

    @Test
    void isPolicyMet_NoChainsPresent_ReturnsFalse() {
        // when
        final boolean result = sut.isPolicyMet(spdmValidChains);

        // then
        assertFalse(result);
    }

    @Test
    void isPolicyMet_BothChainsPresent_ReturnsTrue() {
        // given
        spdmValidChains.add(attChain);
        spdmValidChains.add(iidChain);

        // when
        final boolean result = sut.isPolicyMet(spdmValidChains);

        // then
        assertTrue(result);
    }

    @Test
    void isPolicyMet_OnlyAttChainPresent_IidFlow_ReturnsFalse() {
        // given
        spdmValidChains.add(attChain);
        when(iidFlowDetector.isIidFlow(Optional.of(attCert))).thenReturn(true);

        // when
        final boolean result = sut.isPolicyMet(spdmValidChains);

        // then
        assertFalse(result);
    }

    @Test
    void isPolicyMet_OnlyAttChainPresent_NotIidFlow_ReturnsTrue() {
        // given
        spdmValidChains.add(attChain);
        when(iidFlowDetector.isIidFlow(Optional.of(attCert))).thenReturn(false);

        // when
        final boolean result = sut.isPolicyMet(spdmValidChains);

        // then
        assertTrue(result);
    }

    @Test
    void isPolicyMet_OnlyIidChainPresent_ReturnsFalse() {
        // given
        spdmValidChains.add(iidChain);

        // when
        final boolean result = sut.isPolicyMet(spdmValidChains);

        // then
        assertFalse(result);
    }

    @Test
    void equivalentChainValidated_AttChain_ValidAttChainPresent_ReturnsTrue() {
        // given
        spdmValidChains.add(attChain);

        // when
        final boolean result = sut.equivalentChainValidated(spdmValidChains, attChain);

        // then
        assertTrue(result);
    }

    @Test
    void equivalentChainValidated_AttChain_ValidAttChainNotPresent_ReturnsFalse() {
        // when
        final boolean result = sut.equivalentChainValidated(spdmValidChains, attChain);

        // then
        assertFalse(result);
    }

    @Test
    void equivalentChainValidated_IidChain_ValidIidChainPresent_ReturnsTrue() {
        // given
        spdmValidChains.add(iidChain);

        // when
        final boolean result = sut.equivalentChainValidated(spdmValidChains, iidChain);

        // then
        assertTrue(result);
    }

    @Test
    void equivalentChainValidated_IidChain_ValidIidChainNotPresent_ValidAttChainPresent_IidFlow_ReturnsFalse() {
        // given
        spdmValidChains.add(attChain);
        when(iidFlowDetector.isIidFlow(Optional.of(attCert))).thenReturn(true);

        // when
        final boolean result = sut.equivalentChainValidated(spdmValidChains, iidChain);

        // then
        assertFalse(result);
    }

    @Test
    void equivalentChainValidated_IidChain_ValidIidChainNotPresent_ValidAttChainPresent_NotIidFlow_ReturnsTrue() {
        // given
        spdmValidChains.add(attChain);
        when(iidFlowDetector.isIidFlow(Optional.of(attCert))).thenReturn(false);

        // when
        final boolean result = sut.equivalentChainValidated(spdmValidChains, iidChain);

        // then
        assertTrue(result);
    }

    @Test
    void equivalentChainValidated_IidChain_ValidIidChainNotPresent_ValidAttChainNotPresent_IidFlow_ReturnsFalse() {
        // given
        when(iidFlowDetector.isIidFlow(Optional.empty())).thenReturn(true);

        // when
        final boolean result = sut.equivalentChainValidated(spdmValidChains, iidChain);

        // then
        assertFalse(result);
    }

    @Test
    void equivalentChainValidated_IidChain_ValidIidChainNotPresent_ValidAttChainNotPresent_NotIidFlow_ReturnsTrue() {
        // given
        when(iidFlowDetector.isIidFlow(Optional.empty())).thenReturn(false);

        // when
        final boolean result = sut.equivalentChainValidated(spdmValidChains, iidChain);

        // then
        assertTrue(result);
    }
}
