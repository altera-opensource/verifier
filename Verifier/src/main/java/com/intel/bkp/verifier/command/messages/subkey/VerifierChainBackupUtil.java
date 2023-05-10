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

package com.intel.bkp.verifier.command.messages.subkey;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.nio.file.Path;
import java.security.SecureRandom;

import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
@NoArgsConstructor
public class VerifierChainBackupUtil {

    public void backupExistingFile(File chainFile) {
        final String parentDir = getParentDirectory(chainFile);
        final String newFileName = getNewFileName(chainFile);
        final File newFile = new File(parentDir, newFileName);
        if (!chainFile.renameTo(newFile)) {
            log.error("Failed to rename existing chain QKY file to: {}.\n"
                + "If the file does not exist anymore please repeat the operation.\n"
                + "Otherwise, please check that user has WRITE file permission.", newFileName);
        }

        log.info("Renamed existing chain QKY file to: {}", newFileName);
    }

    String getParentDirectory(File chainFile) {
        return chainFile.toPath().getParent().toString();
    }

    String getNewFileName(File chainFile) {
        final Path fileName = chainFile.toPath().getFileName();
        final long timestamp = getTimestamp();
        final String randomizedHex = getRandomizedHex();
        return String.format("%s.backup_%d_%s", fileName, timestamp, randomizedHex);
    }

    long getTimestamp() {
        return System.currentTimeMillis();
    }

    String getRandomizedHex() {
        final byte[] randomized = new byte[Integer.BYTES];
        new SecureRandom().nextBytes(randomized);
        return toHex(randomized);
    }
}
