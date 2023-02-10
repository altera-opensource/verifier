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

import com.intel.bkp.fpgacerts.verification.RootHashVerifier;
import com.intel.bkp.verifier.exceptions.SpdmCommandFailedException;
import com.intel.bkp.verifier.exceptions.ValidChainNotFoundException;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.service.sender.SpdmGetCertificateMessageSender;
import com.intel.bkp.verifier.service.sender.SpdmGetDigestMessageSender;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.List;

import static com.intel.bkp.verifier.Utils.COMMON_PRE_FOLDER;
import static com.intel.bkp.verifier.Utils.ROOT_CERT;
import static com.intel.bkp.verifier.Utils.prepareEfuseChain;
import static com.intel.bkp.verifier.Utils.prepareIidChain;
import static com.intel.bkp.verifier.Utils.readCertificate;
import static com.intel.bkp.verifier.service.certificate.DiceChainType.ATTESTATION;
import static com.intel.bkp.verifier.service.certificate.DiceChainType.IID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmChainSearcherTest {

    public static final VerifierRuntimeException VERIFIER_RUNTIME_EXCEPTION =
        new VerifierRuntimeException("Validation failed.");
    private static final int SLOT_0 = 0;
    private static final int SLOT_1 = 1;
    private static final int SLOT_3 = 3;
    public static final List<Integer> FILLED_SLOTS = List.of(SLOT_0, SLOT_1, SLOT_3);
    private static final byte[] DEVICE_ID = {1, 2};
    private static final byte[] EFUSE_CHAIN = prepareEfuseChain();
    private static final byte[] IID_CHAIN = prepareIidChain();
    private static final byte[] INVALID_CHAIN = {8, 9};
    private static final X509Certificate rootCert = readCertificate(COMMON_PRE_FOLDER, ROOT_CERT);
    private static final String TRUSTED_ROOT_HASH = "ABCD";

    @Mock
    private SpdmGetDigestMessageSender spdmGetDigestMessageSender;
    @Mock
    private SpdmGetCertificateMessageSender spdmGetCertificateMessageSender;
    @Mock
    private SpdmChainPolicyProvider spdmChainPolicyProvider;
    @Mock
    private SpdmDiceAttestationRevocationService diceAttestationRevocationService;
    @Mock
    private RootHashVerifier rootHashVerifier;
    @Mock
    private ValidChainNotFoundHandler validChainNotFoundHandler;

    private SpdmChainSearcher sut;

    @BeforeEach
    void setUp() throws Exception {
        sut = new SpdmChainSearcher(spdmGetDigestMessageSender, spdmGetCertificateMessageSender,
            spdmChainPolicyProvider, diceAttestationRevocationService, rootHashVerifier, TRUSTED_ROOT_HASH,
            validChainNotFoundHandler);
        when(spdmGetDigestMessageSender.send()).thenReturn(FILLED_SLOTS);
    }


    @Test
    void searchValidChains_getFilledSlotsFails_RunsHandlerAndThrows() throws Exception {
        // given
        when(spdmGetDigestMessageSender.send()).thenThrow(new SpdmCommandFailedException(1L));

        // when-then
        assertThrows(ValidChainNotFoundException.class, () -> sut.searchValidChains(DEVICE_ID));

        // then
        verify(validChainNotFoundHandler).run(DEVICE_ID);
        verifyNoInteractions(spdmGetCertificateMessageSender);
        verifyNoInteractions(spdmChainPolicyProvider);
    }

    @Test
    void searchValidChain_PolicyMetImmediately_DoesNotSearchInSlotsAndReturnsEmptyChains() {
        // given
        when(spdmChainPolicyProvider.isPolicyMet(any())).thenReturn(true);

        // when
        final SpdmValidChains result = sut.searchValidChains(DEVICE_ID);

        // then
        verifyNoInteractions(spdmGetCertificateMessageSender);
        assertFalse(result.contains(ATTESTATION));
        assertFalse(result.contains(IID));
    }

    @Test
    void searchValidChain_NoTrustedChain_RunsHandlerAndThrows() throws Exception {
        // given
        when(rootHashVerifier.verifyRootHash(rootCert, TRUSTED_ROOT_HASH)).thenReturn(false);
        when(spdmChainPolicyProvider.isPolicyMet(any())).thenReturn(false);

        when(spdmGetCertificateMessageSender.send(SLOT_0)).thenReturn(EFUSE_CHAIN);
        when(spdmGetCertificateMessageSender.send(SLOT_1)).thenReturn(IID_CHAIN);

        // when-then
        assertThrows(ValidChainNotFoundException.class, () -> sut.searchValidChains(DEVICE_ID));

        // then
        verify(spdmGetCertificateMessageSender, times(FILLED_SLOTS.size())).send(anyInt());
        verify(validChainNotFoundHandler).run(DEVICE_ID);
    }

    @Test
    void searchValidChain_PolicyMetByAttChain_StopsSearchingAfterFindingAttChainAndReturnsAttChain() throws Exception {
        // given
        mockRootIsTrusted();
        mockPolicyMetByOnlyAttestationChain();

        when(spdmGetCertificateMessageSender.send(SLOT_0)).thenReturn(EFUSE_CHAIN);

        // when
        final SpdmValidChains result = sut.searchValidChains(DEVICE_ID);

        // then
        verifyNoMoreInteractions(spdmGetCertificateMessageSender);
        assertTrue(result.contains(ATTESTATION));
        assertEquals(SLOT_0, result.get(ATTESTATION).slotId());
        assertFalse(result.contains(IID));
    }

    @Test
    void searchValidChain_ParsingFailsOnSlot_ContinuesSearchingInNextSlots() throws Exception {
        // given
        mockRootIsTrusted();
        mockPolicyMetByOnlyAttestationChain();

        when(spdmGetCertificateMessageSender.send(SLOT_0)).thenThrow(new RuntimeException("TEST"));
        when(spdmGetCertificateMessageSender.send(SLOT_1)).thenReturn(EFUSE_CHAIN);

        // when
        final SpdmValidChains result = sut.searchValidChains(DEVICE_ID);

        // then
        verifyNoMoreInteractions(spdmGetCertificateMessageSender);
        assertTrue(result.contains(ATTESTATION));
        assertEquals(SLOT_1, result.get(ATTESTATION).slotId());
    }

    @Test
    void searchValidChain_PolicyMetByAttAndIidChains_ReturnsAttAndIidChains() throws Exception {
        // given
        mockRootIsTrusted();
        mockPolicyMetByAttestationChainAndIidChain();

        when(spdmGetCertificateMessageSender.send(SLOT_0)).thenReturn(EFUSE_CHAIN);
        when(spdmGetCertificateMessageSender.send(SLOT_1)).thenReturn(IID_CHAIN);

        // when
        final SpdmValidChains result = sut.searchValidChains(DEVICE_ID);

        // then
        verifyNoMoreInteractions(spdmGetCertificateMessageSender);
        assertTrue(result.contains(ATTESTATION));
        assertEquals(SLOT_0, result.get(ATTESTATION).slotId());
        assertTrue(result.contains(IID));
        assertEquals(SLOT_1, result.get(IID).slotId());
    }

    @Test
    void searchValidChain_FirstValidationFailsSecondPasses_ReturnsValidChains() throws Exception {
        // given
        mockRootIsTrusted();
        mockPolicyMetByOnlyAttestationChain();

        when(spdmGetCertificateMessageSender.send(SLOT_0)).thenReturn(EFUSE_CHAIN);
        when(spdmGetCertificateMessageSender.send(SLOT_1)).thenReturn(EFUSE_CHAIN);
        doThrow(VERIFIER_RUNTIME_EXCEPTION).doNothing()
            .when(diceAttestationRevocationService)
            .verifyChain(eq(DEVICE_ID), any());

        // when
        final SpdmValidChains result = sut.searchValidChains(DEVICE_ID);

        // then
        verifyNoMoreInteractions(spdmGetCertificateMessageSender);
        assertTrue(result.contains(ATTESTATION));
        assertEquals(SLOT_1, result.get(ATTESTATION).slotId());
        assertFalse(result.contains(IID));
    }

    @Test
    void searchValidChain_FirstParsingFailsSecondPasses_ReturnsValidChains() throws Exception {
        // given
        mockRootIsTrusted();
        mockPolicyMetByOnlyAttestationChain();

        when(spdmGetCertificateMessageSender.send(SLOT_0)).thenReturn(INVALID_CHAIN);
        when(spdmGetCertificateMessageSender.send(SLOT_1)).thenReturn(EFUSE_CHAIN);

        // when
        final SpdmValidChains result = sut.searchValidChains(DEVICE_ID);

        // then
        verifyNoMoreInteractions(spdmGetCertificateMessageSender);
        assertTrue(result.contains(ATTESTATION));
        assertEquals(SLOT_1, result.get(ATTESTATION).slotId());
        assertFalse(result.contains(IID));
    }

    private void mockRootIsTrusted() {
        when(rootHashVerifier.verifyRootHash(rootCert, TRUSTED_ROOT_HASH)).thenReturn(true);
    }

    private void mockPolicyMetByOnlyAttestationChain() {
        when(spdmChainPolicyProvider.isPolicyMet(any())).thenAnswer(invocation -> {
            SpdmValidChains validChains = invocation.getArgument(0);
            return validChains.contains(ATTESTATION);
        });
    }

    private void mockPolicyMetByAttestationChainAndIidChain() {
        when(spdmChainPolicyProvider.isPolicyMet(any())).thenAnswer(invocation -> {
            SpdmValidChains validChains = invocation.getArgument(0);
            return validChains.contains(ATTESTATION) && validChains.contains(IID);
        });
    }

}
