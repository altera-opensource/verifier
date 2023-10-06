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
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.MessageTag;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

public class SignMessage extends Message {

    @Getter
    private final List<Signer> signerList = new ArrayList<>();

    public SignMessage() {
        setMessageTag(MessageTag.SIGN);
    }

    public void sign() throws CoseException {
        if (getProtectedField() == null) {
            setProtectedField(isEmptyMap(getProtectedMap()) ? new byte[0] : getProtectedMap().EncodeToBytes());
        }

        for (Signer signer : getSignerList()) {
            signer.sign(getProtectedField(), getContentField());
        }
    }

    public boolean validate(Signer signerToUse) throws CoseException {
        for (Signer signer : getSignerList()) {
            if (signer.equals(signerToUse)) {
                return signer.validate(getProtectedField(), getContentField());
            }
        }
        throw new CoseException("Signer not found");
    }

    public void addSigner(Signer signedBy) {
        getSignerList().add(signedBy);
    }

    @Override
    protected void decode(CBORObject cborObject) throws CoseException {
        SignMessageEncoderDecoder.decode(cborObject, this, signatureField -> {
            if (CBORType.Array != signatureField.getType()) {
                throw new CoseException("Invalid SignMessage structure");
            }

            for (int inc = 0; inc < signatureField.size(); inc++) {
                getSignerList().add(Signer.fromData(signatureField.get(inc)));
            }
        });
    }

    @Override
    protected CBORObject encode() throws CoseException {
        sign();
        return SignMessageEncoderDecoder.encode(this, this::getSignatureData);
    }

    private CBORObject getSignatureData() throws CoseException {
        final CBORObject signers = CBORObject.NewArray();
        for (Signer signer : getSignerList()) {
            signers.Add(signer.encode());
        }
        return signers;
    }
}
