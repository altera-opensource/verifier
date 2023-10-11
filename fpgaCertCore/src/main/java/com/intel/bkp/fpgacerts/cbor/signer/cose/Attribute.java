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
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.AttributeType;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.HeaderKeys;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import lombok.Getter;
import lombok.Setter;

import java.util.EnumSet;
import java.util.List;
import java.util.Map;

@Getter
@Setter
public class Attribute {

    private CBORObject protectedMap = CBORObject.NewMap();
    private CBORObject unprotectedMap = CBORObject.NewMap();
    private CBORObject skipSendMap = CBORObject.NewMap();
    private byte[] protectedField = null;
    private byte[] externalDataField = new byte[0];

    public void addAttribute(CBORObject label, CBORObject value, AttributeType attributeType) throws CoseException {
        removeAttribute(label);
        if (!List.of(CBORType.Integer, CBORType.TextString).contains(label.getType())) {
            throw new CoseException("Labels must be integers or strings");
        }
        switch (attributeType) {
            case PROTECTED -> {
                if (protectedField != null) {
                    throw new CoseException("Cannot modify protected attribute if signature has been computed");
                }
                protectedMap.Add(label, value);
            }
            case UNPROTECTED -> unprotectedMap.Add(label, value);
            case SKIP_SEND -> skipSendMap.Add(label, value);
            default -> throw new CoseException("Invalid attribute location given");
        }
    }

    public void addAttribute(HeaderKeys label, CBORObject value, AttributeType attributeType) throws CoseException {
        addAttribute(label.getCborTag(), value, attributeType);
    }

    public void addProtectedAttributes(Map<HeaderKeys, CBORObject> map) throws CoseException {
        for (Map.Entry<HeaderKeys, CBORObject> entry : map.entrySet()) {
            addAttribute(entry.getKey().getCborTag(), entry.getValue(), AttributeType.PROTECTED);
        }
    }

    public boolean isEmptyMap(CBORObject cborObject) {
        return cborObject.size() == 0;
    }

    public CBORObject findAttribute(CBORObject label, EnumSet<AttributeType> attributes) {
        if (attributes.contains(AttributeType.PROTECTED) && protectedMap.ContainsKey(label)) {
            return protectedMap.get(label);
        }
        if (attributes.contains(AttributeType.UNPROTECTED) && unprotectedMap.ContainsKey(label)) {
            return unprotectedMap.get(label);
        }
        if (attributes.contains(AttributeType.SKIP_SEND) && skipSendMap.ContainsKey(label)) {
            return skipSendMap.get(label);
        }
        return null;
    }

    public CBORObject findAttribute(HeaderKeys label) {
        return findAttribute(label.getCborTag(),
                EnumSet.of(AttributeType.PROTECTED, AttributeType.UNPROTECTED, AttributeType.SKIP_SEND));
    }

    public void removeAttribute(CBORObject label) throws CoseException {
        if (protectedMap.ContainsKey(label)) {
            if (protectedField != null) {
                throw new CoseException("Operation would modify integrity protected attributes");
            }
            protectedMap.Remove(label);
        }
        if (unprotectedMap.ContainsKey(label)) {
            unprotectedMap.Remove(label);
        }
        if (skipSendMap.ContainsKey(label)) {
            skipSendMap.Remove(label);
        }
    }
}
