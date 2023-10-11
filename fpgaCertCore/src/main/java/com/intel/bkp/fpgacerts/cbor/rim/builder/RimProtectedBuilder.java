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

package com.intel.bkp.fpgacerts.cbor.rim.builder;

import com.intel.bkp.fpgacerts.cbor.CborTagsConstant;
import com.intel.bkp.fpgacerts.cbor.ProtectedHeaderBuilderBase;
import com.intel.bkp.fpgacerts.cbor.ProtectedHeaderType;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedMetaMap;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedSignersItem;
import com.intel.bkp.fpgacerts.cbor.rim.RimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.utils.CborDateConverter;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RimProtectedBuilder extends ProtectedHeaderBuilderBase<RimProtectedHeader> {

    @Getter
    private ProtectedHeaderType type = ProtectedHeaderType.RIM;

    public static RimProtectedBuilder instance() {
        return new RimProtectedBuilder();
    }

    @Override
    public byte[] buildMetaMap(RimProtectedHeader header) {
        final ProtectedMetaMap metaMap = header.getMetaMap();
        final CBORObject cborArray = CBORObject.NewArray();
        metaMap.getMetaItems().forEach(item -> cborArray.Add(CBORObject.NewMap()
            .Add(ProtectedSignersItem.CBOR_PROT_META_ENTITY_NAME_KEY, item.getEntityName())));

        return CBORObject.NewMap()
            .Add(CborTagsConstant.CBOR_PROT_META_MAP_SIGNER_KEY, cborArray)
            .Add(CborTagsConstant.CBOR_PROT_META_MAP_SIGNATURE_VALIDITY,
                CBORObject.NewMap().Add(CborTagsConstant.CBOR_PROT_META_MAP_NOT_AFTER, CBORObject.FromObjectAndTag(
                    CborDateConverter.toString(metaMap.getSignatureValidity()),
                    CborTagsConstant.CBOR_PROT_META_MAP_DATE)))
                .EncodeToBytes();
    }
}
