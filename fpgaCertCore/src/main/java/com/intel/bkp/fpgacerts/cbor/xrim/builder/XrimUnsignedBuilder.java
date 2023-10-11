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

import com.intel.bkp.fpgacerts.cbor.RimBuilderBase;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimEntityMap;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimUnsigned;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.List;

import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_XRIM_MAIN_TAG;
import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_XRIM_UNSIGNED_TAG;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class XrimUnsignedBuilder extends RimBuilderBase<XrimUnsigned> {

    private boolean standalone = false;

    public static XrimUnsignedBuilder instance() {
        return new XrimUnsignedBuilder();
    }

    public XrimUnsignedBuilder standalone() {
        this.standalone = true;
        return this;
    }

    @Override
    public byte[] build(XrimUnsigned data) {
        CBORObject cborMap = CBORObject.NewOrderedMap();
        cborMap = cborMap.WithTag(CBOR_XRIM_UNSIGNED_TAG);
        if (standalone) {
            cborMap = cborMap.WithTag(CBOR_XRIM_MAIN_TAG);
        }
        return cborMap
            .Add(XrimUnsigned.XRIM_ENTITIES_KEY, buildEntities(data.getEntityMaps()))
            .Add(XrimUnsigned.XRIM_DENY_LIST_KEY, buildDenyList(data.getDenyList()))
            .EncodeToBytes();
    }

    private static CBORObject buildEntities(List<XrimEntityMap> entityMaps) {
        final CBORObject entitiesArray = CBORObject.NewArray();
        entityMaps.forEach(item -> entitiesArray.Add(buildEntitiesMapEntry(item)));
        return entitiesArray;
    }

    private static CBORObject buildEntitiesMapEntry(XrimEntityMap item) {
        return CBORObject.NewMap()
            .Add(XrimEntityMap.XRIM_ENTITY_NAME_KEY, CBORObject.FromObject(item.getEntityName()))
            .Add(XrimEntityMap.XRIM_REG_ID_KEY,
                CBORObject.FromObjectAndTag(item.getRegId(), XrimEntityMap.XRIM_REG_ID_TAG))
            .Add(XrimEntityMap.XRIM_ROLE_KEY, buildRolesList(item.getRoles()));
    }

    private static CBORObject buildRolesList(List<Integer> roles) {
        final CBORObject cborArray = CBORObject.NewArray();
        roles.forEach(item -> cborArray.Add(CBORObject.FromObject(item)));
        return cborArray;
    }

    private static CBORObject buildDenyList(List<String> list) {
        final CBORObject cborArray = CBORObject.NewArray();
        list.forEach(item -> cborArray.Add(CBORObject.FromObject(item)));
        return cborArray;
    }
}
