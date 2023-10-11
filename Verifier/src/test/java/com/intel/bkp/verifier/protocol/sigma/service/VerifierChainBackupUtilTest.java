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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VerifierChainBackupUtilTest {

    @Spy
    private VerifierChainBackupUtil sut = new VerifierChainBackupUtil();

    @Mock
    File mockFile;

    @Test
    void getParentDirectory() {
        // given
        final String expectedParent = "parent";
        final File file = new File(expectedParent + "/test");

        // when
        final String result = sut.getParentDirectory(file);

        // then
        assertEquals(expectedParent, result);
    }

    @Test
    void getNewFileName() {
        // given
        final long expectedTimestamp = 1234L;
        final String expectedHex = "01020304";
        final String fileName = "test";
        final String expectedNewFileName = fileName + ".backup_1234_01020304";
        doReturn(expectedTimestamp).when(sut).getTimestamp();
        doReturn(expectedHex).when(sut).getRandomizedHex();

        final File file = new File("parent/" + fileName);

        // when
        final String result = sut.getNewFileName(file);

        // then
        assertEquals(expectedNewFileName, result);
    }

    @Test
    void backupExistingFile() {
        // given
        final long expectedTimestamp = 1234L;
        final String expectedHex = "01020304";
        final String fileName = "test";
        final String expectedNewFileName = fileName + ".backup_1234_01020304";
        doReturn(expectedTimestamp).when(sut).getTimestamp();
        doReturn(expectedHex).when(sut).getRandomizedHex();

        when(mockFile.toPath()).thenReturn(Path.of("parent/" + fileName));
        final File newFile = new File("parent/" + expectedNewFileName);

        // when
        sut.backupExistingFile(mockFile);

        // then
        verify(mockFile).renameTo(newFile);
    }
}
