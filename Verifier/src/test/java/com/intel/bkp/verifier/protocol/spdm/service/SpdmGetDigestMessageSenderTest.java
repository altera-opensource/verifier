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

package com.intel.bkp.verifier.protocol.spdm.service;

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.protocol.spdm.exceptions.SpdmCommandFailedException;
import com.intel.bkp.protocol.spdm.jna.model.SpdmGetDigestResult;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmGetDigestMessageSenderTest {

    private static final int SLOT_SET = 0;
    private static final byte[] SLOT_MASK = new byte[]{1};
    private static final int HASH_ALG_LEN = CryptoConstants.SHA384_LEN;
    private static final byte[] DIGEST = new byte[HASH_ALG_LEN];


    static {
        // dummy data
        DIGEST[0] = (byte) 0x02;
        DIGEST[1] = (byte) 0x04;
    }

    @Mock
    private SpdmProtocol spdmProtocol;

    private SpdmGetDigestMessageSender sut;

    @BeforeEach
    void setUp() {
        sut = new SpdmGetDigestMessageSender(spdmProtocol);
    }

    @Test
    void send() throws SpdmCommandFailedException {
        // given
        final SpdmGetDigestResult getDigestResult = new SpdmGetDigestResult(SLOT_MASK, DIGEST, HASH_ALG_LEN);
        when(spdmProtocol.getDigest()).thenReturn(getDigestResult);

        // when
        final List<Integer> result = sut.send();

        // then
        assertEquals(1, result.size());
        assertTrue(result.contains(SLOT_SET));
    }
}
