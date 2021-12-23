/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

import com.intel.bkp.ext.core.manufacturing.model.PufType;
import com.intel.bkp.ext.utils.ByteBufferSafe;
import com.intel.bkp.ext.utils.ByteSwap;
import com.intel.bkp.verifier.command.messages.VerifierDHCertBuilder;
import com.intel.bkp.verifier.command.messages.VerifierDhEntryManager;
import com.intel.bkp.verifier.model.RootChainType;

import java.nio.ByteBuffer;

import static com.intel.bkp.ext.utils.ByteSwapOrder.B2L;
import static com.intel.bkp.ext.utils.HexConverter.fromHex;
import static com.intel.bkp.verifier.command.Magic.CREATE_SUBKEY;

public class CreateAttestationSubKeyMessageBuilder {

    private static final int DH_PUBLIC_KEY_LEN = 96;
    private static final int RESERVED1_LEN = 4;
    private static final int RESERVED2_LEN = 12;
    private static final int CONTEXT_LEN = 28;
    private static final int COUNTER_LEN = Integer.BYTES;

    private final byte[] reservedHeader = new byte[Integer.BYTES];
    private final byte[] magic = ByteSwap.getSwappedArray(CREATE_SUBKEY.getCode(), B2L);
    private final byte[] reserved1 = new byte[RESERVED1_LEN];
    private final byte[] verifierDhPubKey = new byte[DH_PUBLIC_KEY_LEN];
    private final byte[] attestationCertificateType = new byte[Integer.BYTES];
    private final byte[] reserved2 = new byte[RESERVED2_LEN];
    private final byte[] verifierInputContext = new byte[CONTEXT_LEN];
    private final byte[] verifierCounter = new byte[COUNTER_LEN];
    private byte[] userKeyChain = new byte[0];

    private VerifierDHCertBuilder verifierDHCertBuilder = new VerifierDHCertBuilder();
    private VerifierDhEntryManager verifierDhEntryManager = new VerifierDhEntryManager();

    public CreateAttestationSubKeyMessageBuilder verifierDhPubKey(byte[] verifierDhPubKey) {
        ByteBufferSafe.wrap(verifierDhPubKey).getAll(this.verifierDhPubKey);
        return this;
    }

    public CreateAttestationSubKeyMessageBuilder pufType(PufType pufType) {
        byte[] pufTypeArray =
            ByteSwap.getSwappedArray(pufType.ordinal(), B2L);
        ByteBufferSafe.wrap(pufTypeArray).getAll(this.attestationCertificateType);
        return this;
    }

    public CreateAttestationSubKeyMessageBuilder context(String context) {
        ByteBuffer.allocate(CONTEXT_LEN)
            .put(fromHex(context))
            .rewind()
            .get(this.verifierInputContext);
        return this;
    }

    public CreateAttestationSubKeyMessageBuilder counter(int counter) {
        byte[] swapped = ByteSwap.getSwappedArray(counter, B2L);
        ByteBufferSafe.wrap(swapped).getAll(this.verifierCounter);
        return this;
    }

    public CreateAttestationSubKeyMessageBuilder userKeyChain() {
        byte[] parentKeyChain = verifierDHCertBuilder.getChain(RootChainType.SINGLE);
        byte[] dhEntry = verifierDhEntryManager.getDhEntry(getDataToSign());
        this.userKeyChain = ByteBuffer.allocate(parentKeyChain.length + dhEntry.length)
            .put(parentKeyChain).put(dhEntry).array();
        return this;
    }

    public CreateAttestationSubKeyMessage build() {
        CreateAttestationSubKeyMessage message = new CreateAttestationSubKeyMessage();
        message.setReservedHeader(reservedHeader);
        message.setMagic(magic);
        message.setReserved1(reserved1);
        message.setVerifierDhPubKey(verifierDhPubKey);
        message.setAttestationCertificateType(attestationCertificateType);
        message.setReserved2(reserved2);
        message.setVerifierInputContext(verifierInputContext);
        message.setVerifierCounter(verifierCounter);
        message.setUserKeyChain(userKeyChain);
        return message;
    }

    public CreateAttestationSubKeyMessageBuilder parse(byte[] message) {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(message)
            .get(reservedHeader)
            .get(magic)
            .get(reserved1)
            .get(verifierDhPubKey)
            .get(attestationCertificateType)
            .get(reserved2)
            .get(verifierInputContext)
            .get(verifierCounter);
        userKeyChain = buffer.getRemaining();
        return this;
    }

    private byte[] getDataToSign() {
        return ByteBuffer.allocate(
            magic.length
                + reserved1.length
                + verifierDhPubKey.length
                + attestationCertificateType.length
                + reserved2.length
                + verifierInputContext.length
                + verifierCounter.length)
            .put(magic)
            .put(reserved1)
            .put(verifierDhPubKey)
            .put(attestationCertificateType)
            .put(reserved2)
            .put(verifierInputContext)
            .put(verifierCounter)
            .array();
    }
}
