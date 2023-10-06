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
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.AttributeType;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.HeaderKeys;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.KeyKeys;
import com.intel.bkp.fpgacerts.cbor.signer.cose.sign.CborSigner;
import com.intel.bkp.fpgacerts.cbor.signer.cose.sign.SignatureVerifier;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Optional;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Signer extends Attribute {

    private static final String CONTEXT_STRING = "Signature";

    @Setter
    @Getter
    private byte[] signature;
    @Setter
    private String contextString = CONTEXT_STRING;
    @Setter
    private CborKeyPair cborKeyPair;

    public static Signer fromOneKey(CborKeyPair key) throws CoseException {
        final var signer = new Signer();
        signer.setupKey(key);
        return signer;
    }

    public static Signer fromData(CBORObject cborObject) throws CoseException {
        final var signer = new Signer();
        signer.decode(cborObject);
        return signer;
    }

    public void setKey(CborKeyPair keyIn) throws CoseException {
        setupKey(keyIn);
    }

    public void sign(byte[] rgbBodyProtected, byte[] rgbContent) throws CoseException {
        if (getProtectedField() == null) {
            setProtectedField(getProtectedMap().size() == 0 ? new byte[0] : getProtectedMap().EncodeToBytes());
        }

        final var payload = CBORObject.NewArray()
            .Add(contextString)
            .Add(rgbBodyProtected)
            .Add(getProtectedField())
            .Add(getExternalDataField())
            .Add(rgbContent)
            .EncodeToBytes();

        final var alg = AlgorithmId.fromCbor(findAttribute(HeaderKeys.ALGORITHM));
        signature = new CborSigner().sign(payload, alg, cborKeyPair);
    }

    public boolean validate(byte[] bodyProtected, byte[] content) throws CoseException {
        final var payload = CBORObject.NewArray()
            .Add(contextString)
            .Add(bodyProtected)
            .Add(getProtectedField())
            .Add(getExternalDataField())
            .Add(content)
            .EncodeToBytes();

        final var alg = AlgorithmId.fromCbor(findAttribute(HeaderKeys.ALGORITHM));
        return SignatureVerifier.verify(alg, payload, signature, cborKeyPair);
    }

    private void decode(CBORObject cborObject) throws CoseException {
        verifyCborStructure(cborObject);

        setProtectedField(cborObject.get(0).GetByteString());
        if (getProtectedField().length == 0) {
            setProtectedMap(CBORObject.NewMap());
        } else {
            Optional.ofNullable(CBORObject.DecodeFromBytes(getProtectedField()))
                .ifPresent(this::setProtectedMap);
            if (getProtectedMap().size() == 0) {
                setProtectedField(new byte[0]);
            }
        }

        setUnprotectedMap(cborObject.get(1));

        if (CBORType.ByteString == cborObject.get(2).getType()) {
            signature = cborObject.get(2).GetByteString();
        } else if (!cborObject.get(2).isNull()) {
            throw new CoseException("Invalid Signer structure");
        }
    }

    protected CBORObject encode() throws CoseException {
        if (signature == null) {
            throw new CoseException("Message not yet signed");
        }

        return CBORObject.NewArray()
            .Add(getProtectedField())
            .Add(getUnprotectedMap())
            .Add(signature);
    }

    private void setupKey(CborKeyPair key) throws CoseException {
        CBORObject cn2;
        CBORObject cn;

        cborKeyPair = key;

        if (signature != null) {
            return;
        }

        cn = key.get(KeyKeys.ALGORITHM);
        if (cn != null) {
            cn2 = findAttribute(HeaderKeys.ALGORITHM);
            if (cn2 == null) {
                addAttribute(HeaderKeys.ALGORITHM, cn, AttributeType.PROTECTED);
            }
        }

        cn = key.get(KeyKeys.KEY_ID);
        if (cn != null) {
            cn2 = findAttribute(HeaderKeys.KID);
            if (cn2 == null) {
                addAttribute(HeaderKeys.KID, cn, AttributeType.UNPROTECTED);
            }
        }
    }

    private static void verifyCborStructure(CBORObject cborObject) throws CoseException {
        if (CBORType.Array != cborObject.getType()) {
            throw new CoseException("Invalid Signer structure");
        }

        if (3 != cborObject.size()) {
            throw new CoseException("Invalid Signer structure");
        }

        if (CBORType.ByteString != cborObject.get(0).getType()) {
            throw new CoseException("Invalid Signer structure");
        }

        if (CBORType.Map != cborObject.get(1).getType()) {
            throw new CoseException("Invalid Signer structure");
        }
    }
}
