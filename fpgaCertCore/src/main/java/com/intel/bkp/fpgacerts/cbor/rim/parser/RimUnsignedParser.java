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

package com.intel.bkp.fpgacerts.cbor.rim.parser;

import com.intel.bkp.fpgacerts.cbor.CborParserBase;
import com.intel.bkp.fpgacerts.cbor.LocatorItem;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.utils.HexConverter.toHex;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RimUnsignedParser extends CborParserBase<RimUnsigned> {

    private static final RimCoMIDParser RIM_CO_MID_CONVERTER = RimCoMIDParser.instance();

    public static RimUnsignedParser instance() {
        return new RimUnsignedParser();
    }

    @Override
    public RimUnsigned parse(CBORObject cbor) {
        final var manifestId = toHex(cbor.get(RimUnsigned.CBOR_MANIFEST_ID_KEY).GetByteString());
        final var comIdBytes = cbor.get(RimUnsigned.CBOR_COMID_KEY).get(0).GetByteString();
        final var comIdObj = RIM_CO_MID_CONVERTER.parse(comIdBytes);
        final List<LocatorItem> locators = new ArrayList<>();
        for (int inc = 0; inc < cbor.get(RimUnsigned.CBOR_LOCATORS_KEY).size(); inc++) {
            final String link = cbor.get(RimUnsigned.CBOR_LOCATORS_KEY).get(inc).get(0).AsString();
            locators.add(new LocatorItem(LocatorType.parse(link), link));
        }

        final var profile = toHex(cbor.get(RimUnsigned.CBOR_PROFILE_KEY).get(0).GetByteString());
        return RimUnsigned.builder()
            .manifestId(manifestId)
            .comIds(List.of(comIdObj))
            .locators(locators)
            .profile(List.of(profile))
            .build();
    }
}
