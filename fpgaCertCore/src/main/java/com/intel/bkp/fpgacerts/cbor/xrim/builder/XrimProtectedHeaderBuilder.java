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

import com.intel.bkp.fpgacerts.cbor.ProtectedHeaderBuilderBase;
import com.intel.bkp.fpgacerts.cbor.ProtectedHeaderType;
import com.intel.bkp.fpgacerts.cbor.utils.CborDateConverter;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimProtectedMetaMap;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_PROT_META_MAP_DATE;
import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_PROT_META_MAP_SIGNATURE_VALIDITY;
import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_PROT_META_MAP_SIGNER_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.ProtectedSignersItem.CBOR_PROT_META_ENTITY_NAME_KEY;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class XrimProtectedHeaderBuilder extends ProtectedHeaderBuilderBase<XrimProtectedHeader> {

    @Getter
    private ProtectedHeaderType type = ProtectedHeaderType.XRIM;

    public static XrimProtectedHeaderBuilder instance() {
        return new XrimProtectedHeaderBuilder();
    }

    @Override
    public byte[] buildMetaMap(XrimProtectedHeader header) {
        final XrimProtectedMetaMap metaMap = header.getMetaMap();
        return CBORObject.NewMap()
            .Add(CBOR_PROT_META_MAP_SIGNER_KEY, CBORObject.NewMap()
                .Add(CBOR_PROT_META_ENTITY_NAME_KEY, metaMap.getMetaItem().getEntityName()))
            .Add(CBOR_PROT_META_MAP_SIGNATURE_VALIDITY, CBORObject.FromObjectAndTag(
                CborDateConverter.toString(metaMap.getIssuedDate()), CBOR_PROT_META_MAP_DATE))
            .EncodeToBytes();
    }

}
