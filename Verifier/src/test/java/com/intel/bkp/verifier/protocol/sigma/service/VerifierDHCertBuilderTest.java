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

package com.intel.bkp.verifier.protocol.sigma.service;

import com.intel.bkp.verifier.protocol.sigma.model.RootChainType;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.utils.VerifierFileReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VerifierDHCertBuilderTest {

    private static final String SINGLE = "SINGLE";
    private static final String MULTI = "MULTI";

    @Mock
    private AppContext appContext;

    @Mock
    private VerifierFileReader fileReader;

    @Mock
    private VerifierRootChainManager verifierRootChainManager;

    @InjectMocks
    private VerifierDHCertBuilder sut;

    @Test
    void getChain_WithSingle_ReturnsSingle() {
        // given
        when(verifierRootChainManager.getChainPath(appContext, RootChainType.SINGLE)).thenReturn(SINGLE);

        // when
        sut.getChain(appContext, RootChainType.SINGLE);

        // then
        verify(verifierRootChainManager).verifyIfChainFileIsValid(appContext, RootChainType.SINGLE);
        verify(fileReader).readFileBytes(SINGLE);
    }

    @Test
    void getChain_WithMulti_ReturnsMulti() {
        // given
        when(verifierRootChainManager.getChainPath(appContext, RootChainType.MULTI)).thenReturn(MULTI);

        // when
        sut.getChain(appContext, RootChainType.MULTI);

        // then
        verify(verifierRootChainManager).verifyIfChainFileIsValid(appContext, RootChainType.MULTI);
        verify(fileReader).readFileBytes(MULTI);
    }
}
