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

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.psgcertificate.PsgSignatureBuilder;
import com.intel.bkp.core.psgcertificate.model.PsgSignature;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.crypto.exceptions.HMacProviderException;
import com.intel.bkp.crypto.hmac.IHMacProvider;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwap;
import lombok.RequiredArgsConstructor;

import java.nio.ByteBuffer;
import java.util.function.Function;

import static com.intel.bkp.command.model.Magic.SIGMA_M3;
import static com.intel.bkp.utils.ByteSwapOrder.B2L;

@RequiredArgsConstructor
public class SigmaM3MessageBuilder {

    private static final int SIGNATURE_LEN = 112;

    public static final int DH_PUBLIC_KEY_LEN = 96;
    public static final int MAC_LEN = 48;

    private final byte[] reservedHeader = new byte[Integer.BYTES];
    private final byte[] magic = ByteSwap.getSwappedArray(SIGMA_M3.getCode(), B2L);
    private final byte[] sdmSessionId = new byte[Integer.BYTES];
    private final byte[] bkpsDhPubKey = new byte[DH_PUBLIC_KEY_LEN];
    private final byte[] deviceDhPubKey = new byte[DH_PUBLIC_KEY_LEN];
    private final byte[] signature = new byte[SIGNATURE_LEN];
    private final byte[] mac = new byte[MAC_LEN];

    public SigmaM3MessageBuilder sdmSessionId(byte[] sdmSessionId) {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteSwap.getSwappedArrayByInt(sdmSessionId, B2L));
        buffer.getAll(this.sdmSessionId);
        return this;
    }

    public SigmaM3MessageBuilder bkpsDhPubKey(byte[] bkpsDhPubKey) {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(bkpsDhPubKey);
        buffer.getAll(this.bkpsDhPubKey);
        return this;
    }

    public SigmaM3MessageBuilder deviceDhPubKey(byte[] deviceDhPubKey) {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(deviceDhPubKey);
        buffer.getAll(this.deviceDhPubKey);
        return this;
    }

    public SigmaM3MessageBuilder signature(Function<byte[], byte[]> signatureProvider) {
        byte[] signed = signatureProvider.apply(getDataToSign());

        PsgSignature psgSignature = new PsgSignatureBuilder()
            .signature(signed, PsgSignatureCurveType.SECP384R1)
            .withActor(EndiannessActor.FIRMWARE)
            .build();

        ByteBufferSafe buffer = ByteBufferSafe.wrap(psgSignature.array());
        buffer.getAll(this.signature);
        return this;
    }

    public SigmaM3MessageBuilder mac(IHMacProvider macProvider) throws HMacProviderException {
        byte[] hashed = macProvider.getHash(getDataToMac());
        ByteBufferSafe buffer = ByteBufferSafe.wrap(hashed);
        buffer.getAll(this.mac);
        return this;
    }

    private byte[] getDataToSign() {
        return ByteBuffer.allocate(magic.length + sdmSessionId.length + bkpsDhPubKey.length
                + deviceDhPubKey.length)
            .put(magic)
            .put(sdmSessionId)
            .put(bkpsDhPubKey)
            .put(deviceDhPubKey)
            .array();
    }

    private byte[] getDataToMac() {
        return ByteBuffer.allocate(magic.length + sdmSessionId.length + bkpsDhPubKey.length
                + deviceDhPubKey.length + signature.length)
            .put(magic)
            .put(sdmSessionId)
            .put(bkpsDhPubKey)
            .put(deviceDhPubKey)
            .put(signature)
            .array();
    }

    public SigmaM3Message build() {
        SigmaM3Message sigmaM3Message = new SigmaM3Message();
        sigmaM3Message.setReservedHeader(reservedHeader);
        sigmaM3Message.setMagic(magic);
        sigmaM3Message.setSdmSessionId(sdmSessionId);
        sigmaM3Message.setBkpsDhPubKey(bkpsDhPubKey);
        sigmaM3Message.setDeviceDhPubKey(deviceDhPubKey);
        sigmaM3Message.setSignature(signature);
        sigmaM3Message.setMac(mac);
        return sigmaM3Message;
    }

    public SigmaM3MessageBuilder parse(byte[] message) {
        ByteBufferSafe.wrap(message)
            .get(reservedHeader)
            .get(magic)
            .get(sdmSessionId)
            .get(bkpsDhPubKey)
            .get(deviceDhPubKey)
            .get(signature)
            .getAll(mac);
        return this;
    }

}
