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

package com.intel.bkp.fpgacerts.cbor.xrim.parser;

import com.intel.bkp.fpgacerts.cbor.CborParserBase;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimEntityMap;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimUnsigned;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class XrimUnsignedParser extends CborParserBase<XrimUnsigned> {

    public static XrimUnsignedParser instance() {
        return new XrimUnsignedParser();
    }

    @Override
    public XrimUnsigned parse(CBORObject cbor) {
        final List<XrimEntityMap> entityMaps = parseEntityMaps(cbor.get(XrimUnsigned.XRIM_ENTITIES_KEY));
        final List<String> denyList = parseDenyList(cbor.get(XrimUnsigned.XRIM_DENY_LIST_KEY));
        return XrimUnsigned.builder()
            .entityMaps(entityMaps)
            .denyList(denyList)
            .build();
    }

    private static List<XrimEntityMap> parseEntityMaps(CBORObject cbor) {
        final List<XrimEntityMap> list = new ArrayList<>();
        for (int inc = 0; inc < cbor.size(); inc++) {
            final CBORObject currentCbor = cbor.get(inc);
            list.add(XrimEntityMap.builder()
                .entityName(currentCbor.get(XrimEntityMap.XRIM_ENTITY_NAME_KEY).AsString())
                .regId(currentCbor.get(XrimEntityMap.XRIM_REG_ID_KEY).AsString())
                .roles(parseRoles(currentCbor.get(XrimEntityMap.XRIM_ROLE_KEY)))
                .build());
        }
        return list;
    }

    private static List<Integer> parseRoles(CBORObject cbor) {
        final List<Integer> list = new ArrayList<>();
        for (int inc = 0; inc < cbor.size(); inc++) {
            list.add(cbor.get(inc).AsInt32Value());
        }
        return list;
    }

    private static List<String> parseDenyList(CBORObject cbor) {
        final List<String> list = new ArrayList<>();
        for (int inc = 0; inc < cbor.size(); inc++) {
            list.add(cbor.get(inc).AsString());
        }
        return list;
    }
}
