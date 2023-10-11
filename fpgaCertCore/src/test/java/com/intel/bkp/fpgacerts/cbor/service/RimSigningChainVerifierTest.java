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

package com.intel.bkp.fpgacerts.cbor.service;

import com.intel.bkp.crypto.x509.validation.ChainVerifier;
import com.intel.bkp.fpgacerts.cbor.exception.RimException;
import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import com.intel.bkp.fpgacerts.verification.CrlVerifier;
import com.intel.bkp.fpgacerts.verification.RootHashVerifier;
import com.intel.bkp.test.X509GeneratorUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.utils.ListUtils.toLinkedList;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RimSigningChainVerifierTest {

    private static List<X509Certificate> chain;
    @Mock
    private ChainVerifier chainVerifier;
    @Mock
    private CrlVerifier crlVerifier;
    @Mock
    private RootHashVerifier rootHashVerifier;
    @Mock
    private ICrlProvider crlProvider;

    @BeforeAll
    static void prepareSigningKeyChain() throws Exception {
        final var x509GeneratorUtil = new X509GeneratorUtil();
        chain = x509GeneratorUtil.generateX509ChainList();
    }

    @Test
    void verifyChain_emptyTrustedRootHash_Success() {
        //given
        RimSigningChainVerifier sut =
            new RimSigningChainVerifier(chainVerifier, crlVerifier, rootHashVerifier, Optional.of(new String[]{""}));
        when(chainVerifier.certificates(toLinkedList(chain))).thenReturn(chainVerifier);
        when(rootHashVerifier.verifyRootHash(toLinkedList(chain).getLast(), new String[]{""})).thenReturn(true);
        when(chainVerifier.verify()).thenReturn(true);
        when(crlVerifier.certificates(toLinkedList(chain))).thenReturn(crlVerifier);
        when(crlVerifier.verify()).thenReturn(true);

        //when-then
        assertDoesNotThrow(() -> sut.verifyChain(chain));
    }

    @Test
    void verifyChain_noCrl_Fail() {
        //given
        RimSigningChainVerifier sutWithMockedProvider = new RimSigningChainVerifier(crlProvider, null);

        //when-then
        final var ex = assertThrows(RimException.class, () -> sutWithMockedProvider.verifyChain(chain));

        //then
        assertEquals("One of the certificates in chain is revoked.", ex.getMessage());
    }

    @Test
    void verifyChain_dummyTrustedRootHash_Fail() {
        //given
        RimSigningChainVerifier sutWithMockedProvider = new RimSigningChainVerifier(crlProvider, new String[]{"dummy"});

        //when-then
        final var ex = assertThrows(RimException.class, () -> sutWithMockedProvider.verifyChain(chain));

        //then
        assertEquals("Root hash in X509 attestation chain is different from trusted root hash.", ex.getMessage());
    }

}
