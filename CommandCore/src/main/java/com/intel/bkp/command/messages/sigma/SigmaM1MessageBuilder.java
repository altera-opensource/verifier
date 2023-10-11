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
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwap;
import lombok.RequiredArgsConstructor;

import java.nio.ByteBuffer;
import java.util.function.Function;

import static com.intel.bkp.command.model.Magic.SIGMA_M1;
import static com.intel.bkp.utils.ByteSwapOrder.B2L;

@RequiredArgsConstructor
public class SigmaM1MessageBuilder {

    static final int DH_PUBLIC_KEY_LEN = 96;

    private static final int RESERVED1_LEN = 4;
    private static final int RESERVED2_LEN = 12;


    private final byte[] reservedHeader = new byte[Integer.BYTES];
    private final byte[] magic = ByteSwap.getSwappedArray(SIGMA_M1.getCode(), B2L);
    private final byte[] reserved1 = new byte[RESERVED1_LEN];
    private final byte[] bkpsDhPubKey = new byte[DH_PUBLIC_KEY_LEN];
    private final byte[] pufType = new byte[Integer.BYTES];
    private final byte[] reserved2 = new byte[RESERVED2_LEN];
    private byte[] userKeyChain = new byte[0];

    public SigmaM1MessageBuilder bkpsDhPubKey(byte[] bkpsDhPubKey) {
        ByteBufferSafe.wrap(bkpsDhPubKey).getAll(this.bkpsDhPubKey);
        return this;
    }

    public SigmaM1MessageBuilder pufType(PufType pufType) {
        byte[] pufTypeArray = ByteSwap.getSwappedArray(pufType.ordinal(), B2L);
        ByteBufferSafe.wrap(pufTypeArray).getAll(this.pufType);
        return this;
    }

    public SigmaM1MessageBuilder userKeyChain(byte[] parentKeyChain, Function<byte[], byte[]> getDhEntry) {
        final byte[] dhEntry = getDhEntry.apply(getDataToSign());
        this.userKeyChain = ByteBuffer.allocate(parentKeyChain.length + dhEntry.length)
            .put(parentKeyChain)
            .put(dhEntry)
            .array();
        return this;
    }

    private byte[] getDataToSign() {
        return ByteBuffer.allocate(magic.length + reserved1.length + bkpsDhPubKey.length + pufType.length
                + reserved2.length)
            .put(magic)
            .put(reserved1)
            .put(bkpsDhPubKey)
            .put(pufType)
            .put(reserved2)
            .array();
    }

    public SigmaM1Message build() {
        SigmaM1Message sigmaM1Message = new SigmaM1Message();
        sigmaM1Message.setReservedHeader(reservedHeader);
        sigmaM1Message.setMagic(magic);
        sigmaM1Message.setReserved1(reserved1);
        sigmaM1Message.setBkpsDhPublicKey(bkpsDhPubKey);
        sigmaM1Message.setPufType(pufType);
        sigmaM1Message.setReserved2(reserved2);
        sigmaM1Message.setUserKeyChain(userKeyChain);
        return sigmaM1Message;
    }

    SigmaM1MessageBuilder parse(byte[] message) {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(message)
            .get(reservedHeader)
            .get(magic)
            .get(reserved1)
            .get(bkpsDhPubKey)
            .get(pufType)
            .get(reserved2);

        userKeyChain = buffer.arrayFromRemaining();
        buffer.getAll(userKeyChain);

        return this;
    }

}
