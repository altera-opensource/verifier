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

package com.intel.bkp.verifier.command.messages;

import com.intel.bkp.verifier.command.messages.subkey.ChainFileProvider;
import com.intel.bkp.verifier.command.messages.subkey.VerifierChainBackupUtil;
import com.intel.bkp.verifier.model.RootChainType;
import com.intel.bkp.verifier.model.VerifierKeyParams;
import com.intel.bkp.verifier.model.VerifierRootQkyChain;
import com.intel.bkp.verifier.service.certificate.AppContext;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VerifierRootChainManagerTest {

    private static final String SINGLE = "SINGLE";
    private static final String MULTI = "MULTI";

    @Mock
    private AppContext appContext;

    @Mock
    private VerifierKeyParams verifierKeyParams;

    @Mock
    private VerifierRootQkyChain verifierRootQkyChain;

    @Mock
    private VerifierChainBackupUtil verifierChainBackupUtil;

    @Mock
    private ChainFileProvider chainFileProvider;

    @Mock
    private File mockFile;

    @InjectMocks
    private VerifierRootChainManager sut;

    @Test
    public void verifyIfChainFileIsValid_ForSingle_DoesNotThrow() {
        // given
        mockFile();
        mockFileCanRead();
        mockAppContext();
        when(verifierRootQkyChain.getSingleChainPath()).thenReturn(SINGLE);
        when(chainFileProvider.getChainFile(SINGLE)).thenReturn(mockFile);

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.verifyIfChainFileIsValid(appContext, RootChainType.SINGLE));
    }

    @Test
    public void verifyIfChainFileIsValid_ForMulti_DoesNotThrow() {
        // given
        mockFile();
        mockFileCanRead();
        mockAppContext();
        when(verifierRootQkyChain.getMultiChainPath()).thenReturn(MULTI);
        when(chainFileProvider.getChainFile(MULTI)).thenReturn(mockFile);

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.verifyIfChainFileIsValid(appContext, RootChainType.MULTI));
    }

    @Test
    public void backupExistingChainFile_CallsBackupForBothFiles() {
        // given
        mockFile();
        mockFileCanWrite();
        mockAppContext();
        when(verifierRootQkyChain.getSingleChainPath()).thenReturn(SINGLE);
        when(chainFileProvider.getChainFile(SINGLE)).thenReturn(mockFile);
        when(verifierRootQkyChain.getMultiChainPath()).thenReturn(MULTI);
        when(chainFileProvider.getChainFile(MULTI)).thenReturn(mockFile);

        // when
        sut.backupExistingChainFile(appContext);

        // then
        verify(verifierChainBackupUtil, times(2)).backupExistingFile(mockFile);
    }

    @Test
    public void getChainPath_ForSingle_ReturnsSingle() {
        // given
        mockAppContext();

        // when
        sut.getChainPath(appContext, RootChainType.SINGLE);

        // then
        verify(verifierRootQkyChain).getSingleChainPath();
    }

    @Test
    public void getChainPath_ForMulti_ReturnsMulti() {
        // given
        mockAppContext();

        // when
        sut.getChainPath(appContext, RootChainType.MULTI);

        // then
        verify(verifierRootQkyChain).getMultiChainPath();
    }

    private void mockAppContext() {
        when(appContext.getVerifierKeyParams()).thenReturn(verifierKeyParams);
        when(verifierKeyParams.getVerifierRootQkyChain()).thenReturn(verifierRootQkyChain);
    }

    private void mockFile() {
        when(mockFile.exists()).thenReturn(true);
        when(mockFile.isFile()).thenReturn(true);
    }

    private void mockFileCanRead() {
        when(mockFile.canRead()).thenReturn(true);
    }

    private void mockFileCanWrite() {
        when(mockFile.canWrite()).thenReturn(true);
    }
}
