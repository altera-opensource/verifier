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

import com.intel.bkp.fpgacerts.cbor.rim.RimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.rim.builder.RimProtectedBuilder;
import com.intel.bkp.fpgacerts.cbor.signer.cose.Attribute;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.signer.cose.exception.CoseException;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.xrim.builder.XrimProtectedHeaderBuilder;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class CoseSignerBase {

    public abstract byte[] sign(CborKeyPair cborKeyPair, byte[] cborBytes,
                                RimProtectedHeader protectedHeader) throws CoseException;

    public abstract byte[] sign(CborKeyPair cborKeyPair, byte[] cborBytes,
                                XrimProtectedHeader protectedHeader) throws CoseException;

    public abstract boolean verify(CborKeyPair cborKeyPair, byte[] data);

    protected void addAttributes(RimProtectedHeader protectedHeader, Attribute signMessage) {
        final CBORObject cborMap = RimProtectedBuilder.instance().buildMap(protectedHeader);
        signMessage.setProtectedMap(cborMap);
    }

    protected void addAttributes(XrimProtectedHeader protectedHeader, Attribute signMessage) {
        final CBORObject cborMap = XrimProtectedHeaderBuilder.instance().buildMap(protectedHeader);
        signMessage.setProtectedMap(cborMap);
    }
}
