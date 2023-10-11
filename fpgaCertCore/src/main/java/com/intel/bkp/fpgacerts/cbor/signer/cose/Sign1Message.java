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

/*
 * Copyright (c) 2016,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of COSE-JAVA nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.intel.bkp.fpgacerts.cbor.signer.cose;

import com.intel.bkp.fpgacerts.cbor.signer.cose.exception.CoseException;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.HeaderKeys;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.MessageTag;
import com.intel.bkp.fpgacerts.cbor.signer.cose.sign.CborSigner;
import com.intel.bkp.fpgacerts.cbor.signer.cose.sign.SignatureVerifier;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
public class Sign1Message extends Message {

    private static final String CONTEXT_STRING = "Signature1";

    @Getter
    @Setter
    private String contextField;

    @Getter
    @Setter
    private byte[] signature;

    public Sign1Message() {
        this(true, true);
    }

    public Sign1Message(boolean emitTag, boolean emitContent) {
        setMessageTag(MessageTag.SIGN_1);
        setEmitTag(emitTag);
        setContextField(CONTEXT_STRING);
        setEmitContent(emitContent);
    }

    public void sign(CborKeyPair cborKeyPair) throws CoseException {
        if (isSigned()) {
            return;
        }

        if (getProtectedField() == null) {
            setProtectedField(getProtectedMap().size() > 0 ? getProtectedMap().EncodeToBytes() : new byte[0]);
        }

        final var payload = CBORObject.NewArray()
            .Add(getContextField())
            .Add(getProtectedField())
            .Add(getExternalDataField())
            .Add(getContentField())
            .EncodeToBytes();

        final var alg = AlgorithmId.fromCbor(findAttribute(HeaderKeys.ALGORITHM));
        this.signature = new CborSigner().sign(payload, alg, cborKeyPair);
    }

    public boolean validate(CborKeyPair cborKeyPair) throws CoseException {
        final var payload = CBORObject.NewArray()
            .Add(getContextField())
            .Add(getProtectedMap().size() > 0 ? getProtectedField() : CBORObject.FromObject(new byte[0]))
            .Add(getExternalDataField())
            .Add(getContentField())
            .EncodeToBytes();

        log.trace("Cbor signature payload: {}", toHex(payload));

        final var alg = AlgorithmId.fromCbor(findAttribute(HeaderKeys.ALGORITHM));
        return SignatureVerifier.verify(alg, payload, getSignature(), cborKeyPair);
    }

    @Override
    protected void decode(CBORObject cborObject) throws CoseException {
        SignMessageEncoderDecoder.decode(cborObject, this, signatureField -> {
            if (CBORType.ByteString != signatureField.getType()) {
                throw new CoseException("Invalid SignMessage structure");
            }

            setSignature(signatureField.GetByteString());
        });
    }

    @Override
    protected CBORObject encode() throws CoseException {
        return SignMessageEncoderDecoder.encode(this, this::getSignature);
    }

    private boolean isSigned() {
        return getSignature() != null;
    }
}
