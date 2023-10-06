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
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.Optional;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SignMessageEncoderDecoder {

    public static CBORObject encode(Message message, IEncodeSignatureField callback) throws CoseException {
        final CBORObject obj = CBORObject.NewArray();
        obj.Add(message.getProtectedField());
        obj.Add(message.getUnprotectedMap());
        if (message.isEmitContent()) {
            obj.Add(message.getContentField());
        } else {
            obj.Add(null);
        }
        obj.Add(callback.getSignature());
        return obj;
    }

    public static void decode(CBORObject cborObject, Message message,
                              IDecodeSignatureField callback) throws CoseException {
        verifySignStructureDataSize(cborObject);

        final CBORObject protectedField = cborObject.get(0);
        final CBORObject unprotectedField = cborObject.get(1);
        final CBORObject payloadField = cborObject.get(2);
        final CBORObject signatureField = cborObject.get(3);

        if (CBORType.ByteString == protectedField.getType()) {
            message.setProtectedField(protectedField.GetByteString());
            if (protectedField.GetByteString().length == 0) {
                message.setProtectedMap(CBORObject.NewMap());
            } else {
                Optional.ofNullable(CBORObject.DecodeFromBytes(message.getProtectedField()))
                    .ifPresent(message::setProtectedMap);
                if (message.getProtectedMap().size() == 0) {
                    message.setProtectedField(new byte[0]);
                }
            }
        } else {
            throw new CoseException("Invalid SignMessage structure");
        }

        if (CBORType.Map == unprotectedField.getType()) {
            message.setUnprotectedMap(unprotectedField);
        } else {
            throw new CoseException("Invalid SignMessage structure");
        }

        if (CBORType.ByteString == payloadField.getType()) {
            message.setContentField(payloadField.GetByteString());
        } else if (!payloadField.isNull()) {
            throw new CoseException("Invalid SignMessage structure");
        }

        callback.decode(signatureField);
    }

    private static void verifySignStructureDataSize(CBORObject cborObject) throws CoseException {
        if (cborObject.size() != 4) {
            throw new CoseException("Invalid SignMessage structure");
        }
    }

    public interface IDecodeSignatureField {

        void decode(CBORObject signatureField) throws CoseException;
    }

    public interface IEncodeSignatureField {

        Object getSignature() throws CoseException;
    }
}
