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

package com.intel.bkp.fpgacerts.cbor.xrim.builder;

import com.intel.bkp.fpgacerts.cbor.CborTagsConstant;
import com.intel.bkp.fpgacerts.cbor.RimBuilderBase;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimSigned;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import static com.intel.bkp.utils.HexConverter.fromHex;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class XrimSignedBuilder extends RimBuilderBase<XrimSigned> {

    public static XrimSignedBuilder instance() {
        return new XrimSignedBuilder();
    }

    @Override
    public byte[] build(XrimSigned data) {
        final var cbor = CBORObject.NewArray()
            .WithTag(CborTagsConstant.CBOR_COSE_SIGN_TAG)
            .WithTag(CborTagsConstant.CBOR_XRIM_SIGNED_TAG)
            .WithTag(CborTagsConstant.CBOR_XRIM_MAIN_TAG)
            .Add(CBORObject.FromObject(XrimProtectedHeaderBuilder.instance()
                .build(data.getProtectedData())))
            .Add(CBORObject.NewMap())
            .Add(CBORObject.FromObject(XrimUnsignedBuilder.instance().build(data.getPayload())))
            .Add(CBORObject.FromObject(fromHex(data.getSignature())));
        return cbor.EncodeToBytes();
    }
}
