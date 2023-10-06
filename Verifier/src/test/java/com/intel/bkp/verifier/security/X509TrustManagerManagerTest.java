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

package com.intel.bkp.verifier.security;

import ch.qos.logback.classic.Level;
import com.intel.bkp.core.properties.TrustStore;
import com.intel.bkp.fpgacerts.dp.AcceptAllTrustManager;
import com.intel.bkp.verifier.LoggerTestUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;

import static ch.qos.logback.classic.Level.WARN;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class X509TrustManagerManagerTest {

    private static final String WARNING_LOG = "**WARNING** Skipped SSL verification - using accept all strategy";
    private static final String TRUST_STORE_PATH = "tmpTrustStore.p12";
    private static final String TRUST_STORE_PATH_NON_EXISTENT = "nonExistent.p12";
    private static final String TRUST_STORE_PASSWORD = "keyPass";
    private static final String TRUST_STORE_TYPE = "PKCS12";

    @Mock
    private TrustStore trustStore;

    private LoggerTestUtil loggerTestUtil;

    @TempDir
    File tempDir;

    @InjectMocks
    private X509TrustManagerManager sut;

    @BeforeEach
    void setUp() throws Exception {
        initKeystore();
        loggerTestUtil = LoggerTestUtil.instance(sut.getClass());
    }

    @AfterEach
    void clearLogs() {
        loggerTestUtil.reset();
    }

    @Test
    void getTrustManagers_trustStoreDoesNotExist_verifyLogExists() {
        // given
        when(trustStore.getLocation()).thenReturn(new File(tempDir, TRUST_STORE_PATH_NON_EXISTENT).getAbsolutePath());

        // when
        final var trustManagers = sut.getTrustManagers();

        // then
        assertEquals(AcceptAllTrustManager.class, trustManagers[0].getClass());
        verifyLogExists(WARNING_LOG, WARN);
    }

    @Test
    void getTrustManagers_trustStoreEmpty_verifyLogExists() {
        // given
        when(trustStore.getLocation()).thenReturn("");

        // when
        final var trustManagers = sut.getTrustManagers();

        // then
        assertEquals(AcceptAllTrustManager.class, trustManagers[0].getClass());
        verifyLogExists(WARNING_LOG, WARN);
    }

    @Test
    void getTrustManagers_trustStoreNull_verifyLogExists() {
        // given
        when(trustStore.getLocation()).thenReturn(null);

        // when
        final var trustManagers = sut.getTrustManagers();

        // then
        assertEquals(AcceptAllTrustManager.class, trustManagers[0].getClass());
        verifyLogExists(WARNING_LOG, WARN);
    }

    @Test
    void getTrustManagers_Success() {
        // given
        when(trustStore.getLocation()).thenReturn(new File(tempDir, TRUST_STORE_PATH).getAbsolutePath());
        when(trustStore.getType()).thenReturn(TRUST_STORE_TYPE);
        when(trustStore.getLocation()).thenReturn(new File(tempDir, TRUST_STORE_PATH).getAbsolutePath());
        when(trustStore.getPassword()).thenReturn(TRUST_STORE_PASSWORD);

        // when-then
        assertDoesNotThrow(() -> sut.getTrustManagers());
    }

    private void initKeystore() throws Exception {
        final KeyStore instance = KeyStore.getInstance(TRUST_STORE_TYPE);
        char[] password = TRUST_STORE_PASSWORD.toCharArray();
        instance.load(null, password);
        final File keystoreFile = new File(tempDir, TRUST_STORE_PATH);

        try (FileOutputStream out = new FileOutputStream(keystoreFile)) {
            instance.store(out, password);
        }
    }

    private void verifyLogExists(String log, Level level) {
        assertTrue(loggerTestUtil.contains(log, level));
    }
}
