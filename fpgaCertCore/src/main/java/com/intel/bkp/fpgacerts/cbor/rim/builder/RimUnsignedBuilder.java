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
import com.intel.bkp.fpgacerts.cbor.LocatorItem;
import com.intel.bkp.fpgacerts.cbor.RimBuilderBase;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.List;

import static com.intel.bkp.utils.HexConverter.fromHex;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RimUnsignedBuilder extends RimBuilderBase<RimUnsigned> {

    private static final RimCoMIDBuilder RIM_CO_MID_BUILDER = RimCoMIDBuilder.instance();

    private boolean standalone = false;

    public static RimUnsignedBuilder instance() {
        return new RimUnsignedBuilder();
    }

    public RimUnsignedBuilder standalone() {
        this.standalone = true;
        return this;
    }

    @Override
    public byte[] build(RimUnsigned data) {
        CBORObject cborMap = CBORObject.NewOrderedMap();
        cborMap = cborMap.WithTag(CborTagsConstant.CBOR_RIM_UNSIGNED_TAG);
        if (standalone) {
            cborMap = cborMap.WithTag(CborTagsConstant.CBOR_RIM_MAIN_TAG);
        }
        return cborMap
            .Add(RimUnsigned.CBOR_MANIFEST_ID_KEY, CBORObject.FromObject(fromHex(data.getManifestId())))
            .Add(RimUnsigned.CBOR_COMID_KEY,
                CBORObject.NewArray().Add(CBORObject.FromObjectAndTag(
                    RIM_CO_MID_BUILDER.designRim(isDesign()).build(data.getComIds().get(0)),
                    RimUnsigned.CBOR_COMID_TAG)))
            .Add(RimUnsigned.CBOR_LOCATORS_KEY, buildLocators(data.getLocators()))
            .Add(RimUnsigned.CBOR_PROFILE_KEY, CBORObject.NewArray().Add(
                CBORObject.FromObjectAndTag(fromHex(data.getProfile().get(0)), RimUnsigned.CBOR_PROFILE_TAG)))
            .EncodeToBytes();
    }

    RimUnsignedBuilder designRim(boolean designRim) {
        setDesign(designRim);
        return this;
    }

    private CBORObject buildLocators(List<LocatorItem> data) {
        final CBORObject cborArray = CBORObject.NewArray();

        data.forEach(item -> cborArray.Add(CBORObject.NewMap().Add(CborTagsConstant.CBOR_LOCATOR_ITEM_KEY,
            CBORObject.FromObjectAndTag(item.link(), CborTagsConstant.CBOR_LOCATOR_ITEM_TAG))));

        return cborArray;
    }
}
