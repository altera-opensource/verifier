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

package com.intel.bkp.verifier.command.messages;

import com.intel.bkp.verifier.command.messages.subkey.ChainFileProvider;
import com.intel.bkp.verifier.command.messages.subkey.VerifierChainBackupUtil;
import com.intel.bkp.verifier.model.RootChainType;
import com.intel.bkp.verifier.model.VerifierRootQkyChain;
import com.intel.bkp.verifier.service.certificate.AppContext;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.File;

@Slf4j
@RequiredArgsConstructor
@AllArgsConstructor
public class VerifierRootChainManager {

    private VerifierChainBackupUtil verifierChainBackupUtil = new VerifierChainBackupUtil();
    private ChainFileProvider chainFileProvider = new ChainFileProvider();

    void verifyIfChainFileIsValid(AppContext appContext, RootChainType chainType) {
        final String chainPath = getChainPath(appContext, chainType);
        final File chainFile = chainFileProvider.getChainFile(chainPath);
        if (!isValidFile(chainFile) || !chainFile.canRead()) {
            throw new IllegalArgumentException(
                String.format("Provided chain file does not exist or has insufficient permissions: %s", chainFile));
        }
    }

    String getChainPath(AppContext appContext, RootChainType chainType) {
        final VerifierRootQkyChain verifierRootQkyChain = appContext
            .getVerifierKeyParams()
            .getVerifierRootQkyChain();

        return RootChainType.SINGLE == chainType
               ? verifierRootQkyChain.getSingleChainPath()
               : verifierRootQkyChain.getMultiChainPath();
    }

    public void backupExistingChainFile() {
        backupExistingChainFile(AppContext.instance());
    }

    void backupExistingChainFile(AppContext appContext) {
        backupExistingChainFile(appContext, RootChainType.SINGLE);
        backupExistingChainFile(appContext, RootChainType.MULTI);
    }

    private void backupExistingChainFile(AppContext appContext, RootChainType chainType) {
        final String chainPath = getChainPath(appContext, chainType);
        final File chainFile = chainFileProvider.getChainFile(chainPath);
        if (isValidFile(chainFile)) {
            if (!chainFile.canWrite()) {
                log.error("Old chain file exists but the application has no write permission to rename it: {}",
                    chainFile);
            } else {
                verifierChainBackupUtil.backupExistingFile(chainFile);
            }
        }
    }

    private boolean isValidFile(File chainFile) {
        return chainFile.exists() && chainFile.isFile();
    }
}

