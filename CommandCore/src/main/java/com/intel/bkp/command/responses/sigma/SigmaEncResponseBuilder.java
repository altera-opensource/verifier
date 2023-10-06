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

package com.intel.bkp.command.responses.sigma;

import com.intel.bkp.command.model.StructureType;
import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.crypto.aesctr.AesCtrIvProvider;
import com.intel.bkp.crypto.exceptions.HMacProviderException;
import com.intel.bkp.crypto.hmac.IHMacProvider;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;

import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_ENCRYPTED_PAYLOAD;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_INITIAL_IV;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_MAC;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_MAGIC;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_MSG_RESP_COUNTER;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_PAYLOAD_LEN;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_RESERVED_HEADER;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_SDM_SESSION_ID;

@Getter
@Setter
public class SigmaEncResponseBuilder
    extends StructureBuilder<SigmaEncResponseBuilder, SigmaEncResponse> {

    public static final int SDM_SESSION_ID_LEN = Integer.BYTES;
    public static final int IV_LEN = AesCtrIvProvider.IV_LEN;
    public static final int MAC_LEN = 32;

    private static final int MSG_RESP_COUNTER_LEN = Integer.BYTES;
    private static final int NO_OF_PADDING_BYTES_LEN = 1;
    private static final int RESERVED1_LEN = 8;
    private static final int RESERVED2_LEN = 3;

    private SigmaEncFlowType flowType = SigmaEncFlowType.HEADER_ONLY;
    private byte[] reservedHeader = new byte[Integer.BYTES];
    private byte[] magic = new byte[Integer.BYTES];
    private byte[] sdmSessionId = new byte[SDM_SESSION_ID_LEN];
    private byte[] messageResponseCounter = new byte[MSG_RESP_COUNTER_LEN];
    private byte[] reserved1 = new byte[RESERVED1_LEN];
    private int payloadLen = 0;
    private byte[] initialIv = new byte[IV_LEN];
    private byte numberOfPaddingBytes;
    private byte[] reserved2 = new byte[RESERVED2_LEN];
    private byte[] encryptedPayload = new byte[0];
    private byte[] mac = new byte[MAC_LEN];

    public SigmaEncResponseBuilder() {
        super(StructureType.SIGMA_ENC_RESP);
    }

    @Override
    public SigmaEncResponseBuilder self() {
        return this;
    }

    public SigmaEncResponseBuilder mac(IHMacProvider macProvider) throws HMacProviderException {
        byte[] hashed = macProvider.getHash(getDataToMac());
        ByteBufferSafe.wrap(hashed).getAll(this.mac);
        return this;
    }

    @Override
    public SigmaEncResponse build() {
        SigmaEncResponse enc = new SigmaEncResponse();
        enc.setFlowType(flowType);
        enc.setReservedHeader(convert(reservedHeader, SIGMA_ENC_RESERVED_HEADER));
        enc.setMagic(convert(magic, SIGMA_ENC_MAGIC));
        enc.setSdmSessionId(convert(sdmSessionId, SIGMA_ENC_SDM_SESSION_ID));
        enc.setMessageResponseCounter(convert(messageResponseCounter,
            SIGMA_ENC_MSG_RESP_COUNTER));
        enc.setReserved1(reserved1);
        enc.setPayloadLen(convertInt(payloadLen, SIGMA_ENC_PAYLOAD_LEN));
        enc.setInitialIv(convert(initialIv, SIGMA_ENC_INITIAL_IV));
        enc.setNumberOfPaddingBytes(numberOfPaddingBytes);
        enc.setReserved2(reserved2);
        enc.setEncryptedPayload(convert(encryptedPayload, SIGMA_ENC_ENCRYPTED_PAYLOAD));
        enc.setMac(convert(mac, SIGMA_ENC_MAC));
        return enc;
    }

    @Override
    public SigmaEncResponseBuilder parse(ByteBufferSafe buffer) throws ParseStructureException {
        if (buffer.remaining() > 0) {
            flowType = SigmaEncFlowType.WITH_ENCRYPTED_RESPONSE;
            return parseWithEncryptedResponse(buffer);
        } else {
            flowType = SigmaEncFlowType.HEADER_ONLY;
            return this;
        }
    }

    private SigmaEncResponseBuilder parseWithEncryptedResponse(ByteBufferSafe buffer) {
        buffer
            .get(reservedHeader)
            .get(magic)
            .get(sdmSessionId)
            .get(messageResponseCounter)
            .get(reserved1);
        payloadLen = buffer.getInt();

        reservedHeader = convert(reservedHeader, SIGMA_ENC_RESERVED_HEADER);
        magic = convert(magic, SIGMA_ENC_MAGIC);
        sdmSessionId = convert(sdmSessionId, SIGMA_ENC_SDM_SESSION_ID);
        messageResponseCounter = convert(messageResponseCounter, SIGMA_ENC_MSG_RESP_COUNTER);
        payloadLen = convertInt(payloadLen, SIGMA_ENC_PAYLOAD_LEN);

        encryptedPayload = buffer.arrayFromInt(payloadLen);

        buffer.get(initialIv);
        numberOfPaddingBytes = buffer.getByte();
        buffer.get(reserved2)
            .get(encryptedPayload)
            .getAll(mac);

        initialIv = convert(initialIv, SIGMA_ENC_INITIAL_IV);
        encryptedPayload = convert(encryptedPayload, SIGMA_ENC_ENCRYPTED_PAYLOAD);
        mac = convert(mac, SIGMA_ENC_MAC);

        return this;
    }

    /**
     * Returns data in the format required for verifying mac (as prepared by FW).
     */
    public byte[] getDataToMac() {
        final int capacity = magic.length + sdmSessionId.length + messageResponseCounter.length
            + reserved1.length + Integer.BYTES + initialIv.length + NO_OF_PADDING_BYTES_LEN
            + reserved2.length + encryptedPayload.length;

        return ByteBuffer.allocate(capacity)
            .put(convert(magic, SIGMA_ENC_MAGIC))
            .put(convert(sdmSessionId, SIGMA_ENC_SDM_SESSION_ID))
            .put(convert(messageResponseCounter, SIGMA_ENC_MSG_RESP_COUNTER))
            .put(reserved1)
            .putInt(convertInt(payloadLen, SIGMA_ENC_PAYLOAD_LEN))
            .put(convert(initialIv, SIGMA_ENC_INITIAL_IV))
            .put(numberOfPaddingBytes)
            .put(reserved2)
            .put(convert(encryptedPayload, SIGMA_ENC_ENCRYPTED_PAYLOAD))
            .array();
    }

    /**
     * Returns data in the format required for decrypting the payload (as prepared by FW).
     */
    public byte[] getDataToDecrypt() {
        return encryptedPayload;
    }
}
