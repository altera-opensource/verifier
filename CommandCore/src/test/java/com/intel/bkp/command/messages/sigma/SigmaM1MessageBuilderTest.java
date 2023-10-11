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

package com.intel.bkp.command.messages.sigma;

import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.core.psgcertificate.PsgBlock0EntryBuilder;
import com.intel.bkp.test.RandomUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(MockitoExtension.class)
public class SigmaM1MessageBuilderTest {

    @Test
    public void build_ReturnValidObject() {
        // given
        byte[] mockPsgCert = ByteBuffer.allocate(10)
            .put(new byte[]{1, 2, 3, 4}).array();
        byte[] mockPsgBlock0Entry = ByteBuffer.allocate(10)
            .putInt(PsgBlock0EntryBuilder.MAGIC).put(new byte[]{5, 6, 7, 8}).array();

        SigmaM1Message msg = new SigmaM1MessageBuilder()
            .bkpsDhPubKey(RandomUtils.generateRandomBytes(SigmaM1MessageBuilder.DH_PUBLIC_KEY_LEN))
            .pufType(PufType.EFUSE)
            .userKeyChain(mockPsgCert, bytes -> mockPsgBlock0Entry)
            .build();

        // when
        final byte[] result = msg.array();
        SigmaM1Message resultMessage = new SigmaM1MessageBuilder()
            .parse(result).build();

        // then
        assertNotNull(result);
        assertNotNull(resultMessage);
        assertArrayEquals(msg.getBkpsDhPublicKey(), resultMessage.getBkpsDhPublicKey());
        assertArrayEquals(msg.getPufType(), resultMessage.getPufType());
        assertArrayEquals(msg.getUserKeyChain(), resultMessage.getUserKeyChain());
    }

}
