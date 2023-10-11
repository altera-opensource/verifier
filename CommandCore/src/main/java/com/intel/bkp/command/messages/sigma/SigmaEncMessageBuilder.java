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

import com.intel.bkp.crypto.aesctr.AesCtrIvProvider;
import com.intel.bkp.crypto.exceptions.HMacProviderException;
import com.intel.bkp.crypto.hmac.IHMacProvider;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwap;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static com.intel.bkp.command.model.Magic.SIGMA_ENC;
import static com.intel.bkp.utils.ByteSwapOrder.B2L;

public class SigmaEncMessageBuilder {

    private static final int SDM_SESSION_ID_LEN = Integer.BYTES;
    private static final int MSG_RESP_COUNTER_LEN = Integer.BYTES;
    private static final int NO_OF_PADDING_BYTES_LEN = 1;
    private static final int RESERVED1_LEN = 8;
    private static final int RESERVED2_LEN = 3;

    public static final int IV_LEN = AesCtrIvProvider.IV_LEN;
    public static final int MAC_LEN = 32;

    private final byte[] reservedHeader = new byte[Integer.BYTES];
    private final byte[] magic = ByteSwap.getSwappedArray(SIGMA_ENC.getCode(), B2L);
    private final byte[] sdmSessionId = new byte[SDM_SESSION_ID_LEN];
    private final byte[] messageResponseCounter = new byte[MSG_RESP_COUNTER_LEN];
    private final byte[] reserved1 = new byte[RESERVED1_LEN];
    private int payloadLenLittleEndian = 0;
    private byte[] initialIv = new byte[IV_LEN];
    private byte[] numberOfPaddingBytes = new byte[NO_OF_PADDING_BYTES_LEN];
    private final byte[] reserved2 = new byte[RESERVED2_LEN];
    private byte[] encryptedPayload = new byte[0];
    private final byte[] mac = new byte[MAC_LEN];

    public SigmaEncMessageBuilder sdmSessionId(byte[] sdmSessionId) {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteSwap.getSwappedArrayByInt(sdmSessionId, B2L));
        buffer.getAll(this.sdmSessionId);
        return this;
    }

    public SigmaEncMessageBuilder messageResponseCounter(int messageResponseCounter) {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteSwap.getSwappedArray(messageResponseCounter, B2L));
        buffer.getAll(this.messageResponseCounter);
        return this;
    }

    public SigmaEncMessageBuilder initialIv(byte[] initialIv) {
        ByteBufferSafe.wrap(initialIv).getAll(this.initialIv);
        return this;
    }

    public SigmaEncMessageBuilder encryptedPayload(byte[] encryptedPayload) {
        this.payloadLenLittleEndian = ByteSwap.getSwappedInt(encryptedPayload.length, B2L);
        this.encryptedPayload = encryptedPayload;
        return this;
    }

    public SigmaEncMessageBuilder numberOfPaddingBytes(byte numberOfPaddingBytes) {
        this.numberOfPaddingBytes[0] = numberOfPaddingBytes;
        return this;
    }

    public SigmaEncMessageBuilder mac(IHMacProvider macProvider) throws HMacProviderException {
        byte[] hashed = macProvider.getHash(getDataToMac());
        ByteBufferSafe.wrap(hashed).getAll(this.mac);
        return this;
    }

    private byte[] getDataToMac() {
        return ByteBuffer.allocate(magic.length + sdmSessionId.length + messageResponseCounter.length
                + reserved1.length + Integer.BYTES + initialIv.length + numberOfPaddingBytes.length
                + reserved2.length + encryptedPayload.length)
            .put(magic)
            .put(sdmSessionId)
            .put(messageResponseCounter)
            .put(reserved1)
            .putInt(payloadLenLittleEndian)
            .put(initialIv)
            .put(numberOfPaddingBytes)
            .put(reserved2)
            .put(encryptedPayload)
            .array();
    }

    public SigmaEncMessage build() {
        SigmaEncMessage sigmaEncMessage = new SigmaEncMessage();
        sigmaEncMessage.setReservedHeader(reservedHeader);
        sigmaEncMessage.setMagic(magic);
        sigmaEncMessage.setSdmSessionId(sdmSessionId);
        sigmaEncMessage.setMessageResponseCounter(messageResponseCounter);
        sigmaEncMessage.setReserved1(reserved1);
        sigmaEncMessage.setPayloadLen(payloadLenLittleEndian);
        sigmaEncMessage.setInitialIv(initialIv);
        sigmaEncMessage.setNumberOfPaddingBytes(numberOfPaddingBytes);
        sigmaEncMessage.setReserved2(reserved2);
        sigmaEncMessage.setEncryptedPayload(encryptedPayload);
        sigmaEncMessage.setMac(mac);
        return sigmaEncMessage;
    }

    public SigmaEncMessageBuilder parse(byte[] message) {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(message);
        buffer.get(reservedHeader);
        buffer.get(magic);
        buffer.get(sdmSessionId);
        buffer.get(messageResponseCounter);
        buffer.get(reserved1);
        encryptedPayload = buffer.arrayFromNextInt(ByteOrder.LITTLE_ENDIAN);
        buffer.get(initialIv);
        buffer.get(numberOfPaddingBytes);
        buffer.get(reserved2);
        buffer.get(encryptedPayload);
        payloadLenLittleEndian = ByteSwap.getSwappedInt(encryptedPayload.length, B2L);
        buffer.getAll(mac);
        return this;
    }

}
