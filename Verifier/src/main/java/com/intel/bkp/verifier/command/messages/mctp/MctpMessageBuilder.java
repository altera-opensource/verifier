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

package com.intel.bkp.verifier.command.messages.mctp;


import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import lombok.AccessLevel;
import lombok.Getter;

import java.nio.ByteBuffer;

@Getter(AccessLevel.PACKAGE)
public class MctpMessageBuilder {

    public static final byte MCTP_HEADER_SIZE = Integer.BYTES;
    private static final int MCTP_HEADER = 0x05130000;

    private final byte[] header = ByteSwap.getSwappedArray(MCTP_HEADER, ByteSwapOrder.B2L);
    private byte[] payload = new byte[0];

    public MctpMessageBuilder parse(byte[] message) {
        final ByteBufferSafe buffer = ByteBufferSafe.wrap(message);
        buffer.get(header);
        payload = buffer.getRemaining();
        return this;
    }

    public MctpMessageBuilder parse(ByteBuffer message) {
        final byte[] messageBytes = new byte[message.remaining()];
        message.get(messageBytes);
        parse(messageBytes);
        return this;
    }

    public MctpMessageBuilder withPayload(ByteBuffer payload) {
        this.payload = new byte[payload.remaining()];
        payload.get(this.payload);
        return this;
    }

    public MctpMessage build() {
        final var message = new MctpMessage();
        message.setHeader(header);
        message.setPayload(payload);
        return message;
    }
}
