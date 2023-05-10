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

import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import com.intel.bkp.verifier.command.messages.VerifierRootChainManager;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VerifierKeyManagerTest {

    private static final String KEY_NAME = "KEY_NAME";

    @Mock
    private ISecurityProvider securityProvider;

    @Mock
    private GuidProvider guidProvider;

    @Mock
    private VerifierRootChainManager verifierRootChainManager;

    private VerifierKeyManager sut;

    @BeforeEach
    public void setUp() {
        sut = new VerifierKeyManager(securityProvider, KEY_NAME, guidProvider, verifierRootChainManager);
    }

    @Test
    void initialized_BlankKeyName_ReturnsFalse() {
        // given
        VerifierKeyManager sut =
            new VerifierKeyManager(securityProvider, "", guidProvider, verifierRootChainManager);

        // when
        final boolean result = sut.initialized();

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void initialized_KeyDoesNotExistInEnclave_Throws() {
        // given
        when(securityProvider.existsSecurityObject(KEY_NAME)).thenReturn(false);

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> sut.initialized());
    }

    @Test
    void initialized_ReturnsTrue() {
        // given
        when(securityProvider.existsSecurityObject(KEY_NAME)).thenReturn(true);

        // when
        final boolean result = sut.initialized();

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void initialize_CreatesKeyInEnclave_DoesNotThrow() {
        // given
        final byte[] mockPubKey = { 1, 2 };
        when(guidProvider.generateNewGuid()).thenReturn(KEY_NAME);
        when(securityProvider.existsSecurityObject(KEY_NAME)).thenReturn(true);
        when(securityProvider.getPubKeyFromSecurityObject(KEY_NAME)).thenReturn(mockPubKey);

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.initialize());
        verify(securityProvider).createSecurityObject(SecurityKeyType.EC, KEY_NAME);
        verify(verifierRootChainManager).backupExistingChainFile();
    }

    @Test
    void initialize_FailsToCreateKeyInEnclave_Throws() {
        // given
        when(guidProvider.generateNewGuid()).thenReturn(KEY_NAME);
        when(securityProvider.existsSecurityObject(KEY_NAME)).thenReturn(false);

        // when-then
        Assertions.assertThrows(InternalLibraryException.class, () -> sut.initialize());
        verify(securityProvider, never()).getPubKeyFromSecurityObject(KEY_NAME);
    }
}
