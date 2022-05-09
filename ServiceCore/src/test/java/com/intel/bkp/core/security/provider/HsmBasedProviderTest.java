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
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.spy;

class HsmBasedProviderTest {

    private static final String KEYSTORE_INPUT_PARAM = "myParamTest";
    private static final String PASSWORD_KEYSTORE = "password";
    private final HsmBasedProvider sut = new HsmBasedProvider();
    @Mock
    private KeyStoreSpi keyStoreSpiMock;
    private KeyStore keyStoreMock;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        keyStoreMock = spy(new KeyStore(keyStoreSpiMock, null, "test") {
        });
        try {
            doNothing().when(keyStoreSpiMock).engineLoad(any(), any());
            keyStoreMock.load(null);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }
    }

    @Test
    void load_withEmptyKeystoreInputPath_ThrowsException() {
        Assertions.assertDoesNotThrow(() -> sut.load(keyStoreMock, null, PASSWORD_KEYSTORE)
        );
    }

    @Test
    void load_Success() {
        // when-then
        Assertions.assertDoesNotThrow(() -> sut.load(keyStoreMock, KEYSTORE_INPUT_PARAM, PASSWORD_KEYSTORE));
    }

    @Test
    void store_Success() {
        // when
        Assertions.assertDoesNotThrow(() -> sut.store(keyStoreMock, KEYSTORE_INPUT_PARAM, PASSWORD_KEYSTORE));
    }
}
