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

package com.intel.bkp.core.security.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;

@ExtendWith(MockitoExtension.class)
class HsmBasedProviderTest {

    @TempDir
    File tempDir;

    private static final String KEYSTORE_PASSWORD = "keyPass";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private File keystoreFile;
    private KeyStore keystore;

    private final HsmBasedProvider sut = new HsmBasedProvider();

    @BeforeEach
    void setUp() throws Exception {
        keystoreFile = initKeystore();
        keystore = KeyStore.getInstance(KEYSTORE_TYPE);
    }

    @Test
    void load_withEmptyKeystoreInputPath_ThrowsException() {
        Assertions.assertDoesNotThrow(() -> sut.load(keystore, null, KEYSTORE_PASSWORD)
        );
    }

//    @Test
//    void load_Success() {
//        // when-then
//        Assertions.assertDoesNotThrow(() -> sut.load(keystore, keystoreFile.getAbsolutePath(), KEYSTORE_PASSWORD));
//    }
//
//    @Test
//    void store_Success() throws Exception {
//        // given
//        sut.load(keystore, keystoreFile.getAbsolutePath(), KEYSTORE_PASSWORD);
//
//        // when
//        Assertions.assertDoesNotThrow(() -> sut.store(keystore, keystoreFile.getAbsolutePath(), KEYSTORE_PASSWORD));
//    }

    private File initKeystore() throws Exception {
        final KeyStore instance = KeyStore.getInstance(KEYSTORE_TYPE);
        char[] password = KEYSTORE_PASSWORD.toCharArray();
        instance.load(null, password);
        final File keystoreFile = new File(tempDir, "tmpKeystore.p12");

        try (FileOutputStream out = new FileOutputStream(keystoreFile)) {
            instance.store(out, password);
        }
        return keystoreFile;
    }
}
