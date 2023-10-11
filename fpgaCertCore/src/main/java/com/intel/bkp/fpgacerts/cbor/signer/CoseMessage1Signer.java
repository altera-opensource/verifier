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

package com.intel.bkp.fpgacerts.cbor.signer;

import com.intel.bkp.fpgacerts.cbor.CborTagsConstant;
import com.intel.bkp.fpgacerts.cbor.rim.RimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.signer.cose.Message;
import com.intel.bkp.fpgacerts.cbor.signer.cose.Sign1Message;
import com.intel.bkp.fpgacerts.cbor.signer.cose.exception.CoseException;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.MessageTag;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimProtectedHeader;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static com.intel.bkp.utils.HexConverter.toHex;


@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public class CoseMessage1Signer extends CoseSignerBase {

    public static CoseMessage1Signer instance() {
        return new CoseMessage1Signer();
    }

    @Override
    public byte[] sign(CborKeyPair cborKeyPair, byte[] cborBytes,
                       RimProtectedHeader protectedHeader) throws CoseException {
        final var signMessage = new Sign1Message();

        addAttributes(protectedHeader, signMessage);

        signMessage.setContentField(cborBytes);
        signMessage.sign(cborKeyPair);
        return signMessage.encodeToCBORObject()
            .WithTag(CborTagsConstant.CBOR_RIM_SIGNED_TAG)
            .WithTag(CborTagsConstant.CBOR_RIM_MAIN_TAG)
            .EncodeToBytes();
    }

    @Override
    public byte[] sign(CborKeyPair cborKeyPair, byte[] cborBytes,
                       XrimProtectedHeader protectedHeader) throws CoseException {
        final var signMessage = new Sign1Message();

        addAttributes(protectedHeader, signMessage);

        signMessage.setContentField(cborBytes);
        signMessage.sign(cborKeyPair);
        return signMessage.encodeToCBORObject()
            .WithTag(CborTagsConstant.CBOR_XRIM_SIGNED_TAG)
            .WithTag(CborTagsConstant.CBOR_XRIM_MAIN_TAG)
            .EncodeToBytes();
    }

    @Override
    public boolean verify(CborKeyPair cborKeyPair, byte[] data) {
        log.trace("Verifying data: " + toHex(data));
        try {
            final var msg = (Sign1Message) Message.decodeFromBytes(data, MessageTag.SIGN_1);
            return msg.validate(cborKeyPair);
        } catch (CoseException e) {
            log.error("Failed to verify signature1 " + e.getMessage(), e);
            return false;
        }
    }

}
