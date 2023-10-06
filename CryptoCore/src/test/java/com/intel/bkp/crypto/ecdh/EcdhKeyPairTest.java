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

package com.intel.bkp.crypto.ecdh;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;


/**
 * Unit tests for the EcdhKeyPairTest class.
 *
 * @see EcdhKeyPair
 */

@ExtendWith(MockitoExtension.class)
public class EcdhKeyPairTest {

    @Test
    public void generate_ReturnObject() throws EcdhKeyPairException {
        // when
        final EcdhKeyPair result = EcdhKeyPair.generate();

        // then
        assertNotNull(result);
        assertNotNull(result.getPrivateKey());
        assertNotNull(result.getPublicKey());
    }

    @Test
    public void fromKeyPair_ReturnValidObject() throws Exception {
        // given
        KeyPair keyPair = CryptoUtils.genEcdhBC();

        // when
        final EcdhKeyPair ecdhKeyPair = EcdhKeyPair.fromKeyPair(keyPair);

        // then
        assertNotNull(ecdhKeyPair);
        assertNotNull(ecdhKeyPair.getPrivateKey());
        assertNotNull(ecdhKeyPair.getPublicKey());
    }

    @Test
    public void fromKeyPair_NullKeyPair_ThrowException() {
        // given
        final KeyPair keyPair = null;

        // when
        assertThrows(EcdhKeyPairException.class, () -> EcdhKeyPair.fromKeyPair(keyPair));
    }

    @Test
    public void fromBytes_ValidPub_ReturnValidObject() throws EcdhKeyPairException {
        // given
        final byte[] gaBytes = new byte[]{1, 2, 3, 4};

        // when
        EcdhKeyPair ecdhKeyPair = EcdhKeyPair.fromPublicBytes(gaBytes);

        // then
        assertNotNull(ecdhKeyPair);
        assertNotNull(ecdhKeyPair.getPublicKey());
        assertArrayEquals(gaBytes, ecdhKeyPair.getPublicKey());
        assertNull(ecdhKeyPair.getPrivateKey());
    }

    @Test
    public void fromBytes_NullPubKey_ThrowException() {
        // given
        byte[] gaBytes = null;

        // when
        assertThrows(EcdhKeyPairException.class, () -> EcdhKeyPair.fromPublicBytes(gaBytes));
    }

    @Test
    public void fromBytes_EmptyPubKey_ThrowException() {
        // given
        byte[] gaBytes = new byte[0];

        // when
        assertThrows(EcdhKeyPairException.class, () -> EcdhKeyPair.fromPublicBytes(gaBytes));
    }

}
