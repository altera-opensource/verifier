/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2022 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.command.messages.attestation;

import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.verifier.command.messages.VerifierDHCertBuilder;
import com.intel.bkp.verifier.command.messages.VerifierDhEntryManager;
import com.intel.bkp.verifier.model.RootChainType;
import lombok.NoArgsConstructor;

import java.nio.ByteBuffer;

import static com.intel.bkp.utils.ByteSwapOrder.B2L;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.verifier.command.Magic.GET_MEASUREMENT;

@NoArgsConstructor
public class GetMeasurementMessageBuilder {

    private static final int DH_PUBLIC_KEY_LEN = 96;
    private static final int RESERVED2_LEN = 12;
    private static final int CONTEXT_LEN = 28;
    private static final int COUNTER_LEN = Integer.BYTES;

    private final byte[] reservedHeader = new byte[Integer.BYTES];
    private final byte[] magic = ByteSwap.getSwappedArray(GET_MEASUREMENT.getCode(), B2L);
    private final byte[] flags = new byte[Integer.BYTES];
    private final byte[] verifierDhPubKey = new byte[DH_PUBLIC_KEY_LEN];
    private final byte[] attestationCertificateType = new byte[Integer.BYTES];
    private final byte[] reserved2 = new byte[RESERVED2_LEN];
    private final byte[] verifierInputContext = new byte[CONTEXT_LEN];
    private final byte[] verifierCounter = new byte[COUNTER_LEN];
    private byte[] userKeyChain = new byte[0];

    private VerifierDHCertBuilder verifierDHCertBuilder = new VerifierDHCertBuilder();
    private VerifierDhEntryManager verifierDhEntryManager = new VerifierDhEntryManager();

    public GetMeasurementMessageBuilder verifierDhPubKey(byte[] verifierDhPubKey) {
        ByteBufferSafe.wrap(verifierDhPubKey).getAll(this.verifierDhPubKey);
        return this;
    }

    public GetMeasurementMessageBuilder pufType(PufType pufType) {
        byte[] pufTypeArray =
            ByteSwap.getSwappedArray(pufType.ordinal(), B2L);
        ByteBufferSafe.wrap(pufTypeArray).getAll(this.attestationCertificateType);
        return this;
    }

    public GetMeasurementMessageBuilder context(String context) {
        ByteBuffer.allocate(CONTEXT_LEN)
            .put(fromHex(context))
            .rewind()
            .get(this.verifierInputContext);
        return this;
    }

    public GetMeasurementMessageBuilder counter(int counter) {
        byte[] swapped = ByteSwap.getSwappedArray(counter, B2L);
        ByteBufferSafe.wrap(swapped).getAll(this.verifierCounter);
        return this;
    }

    public GetMeasurementMessageBuilder userKeyChain(RootChainType rootChainType) {
        byte[] parentKeyChain = verifierDHCertBuilder.getChain(rootChainType);
        byte[] dhEntry = verifierDhEntryManager.getDhEntry(getDataToSign());
        this.userKeyChain = ByteBuffer.allocate(parentKeyChain.length + dhEntry.length)
            .put(parentKeyChain).put(dhEntry).array();
        return this;
    }

    public GetMeasurementMessage build() {
        GetMeasurementMessage message = new GetMeasurementMessage();
        message.setReservedHeader(reservedHeader);
        message.setMagic(magic);
        message.setFlags(flags);
        message.setVerifierDhPubKey(verifierDhPubKey);
        message.setAttestationCertificateType(attestationCertificateType);
        message.setReserved2(reserved2);
        message.setVerifierInputContext(verifierInputContext);
        message.setVerifierCounter(verifierCounter);
        message.setUserKeyChain(userKeyChain);
        return message;
    }

    private byte[] getDataToSign() {
        return ByteBuffer.allocate(
            magic.length
                + flags.length
                + verifierDhPubKey.length
                + attestationCertificateType.length
                + reserved2.length
                + verifierInputContext.length
                + verifierCounter.length)
            .put(magic)
            .put(flags)
            .put(verifierDhPubKey)
            .put(attestationCertificateType)
            .put(reserved2)
            .put(verifierInputContext)
            .put(verifierCounter)
            .array();
    }

    public GetMeasurementMessageBuilder parse(byte[] message) {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(message)
            .get(reservedHeader)
            .get(magic)
            .get(flags)
            .get(verifierDhPubKey)
            .get(attestationCertificateType)
            .get(reserved2)
            .get(verifierInputContext)
            .get(verifierCounter);
        userKeyChain = buffer.getRemaining();
        return this;
    }
}
