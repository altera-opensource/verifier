/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.model.evidence;

import com.intel.bkp.verifier.model.dice.FwIdField;
import com.intel.bkp.verifier.model.dice.MaskedVendorInfo;
import com.intel.bkp.verifier.model.dice.TcbInfo;
import com.intel.bkp.verifier.model.dice.TcbInfoField;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

class BaseEvidenceBlockToTcbInfoMapperTest {

    private static final String TYPE = "TYPE";
    private static final String VENDOR = "VENDOR";
    private static final String MODEL = "MODEL";
    private static final String LAYER = "11";
    private static final int LAYER_INT = 11;
    private static final int INDEX = 9;
    private static final String DIGEST = "DIGEST";
    private static final String DIGEST_LOWERCASE = "digest";
    private static final String HASH_ALG = "HASH_ALG";
    private static final FwIdField FWIDS = new FwIdField(HASH_ALG, DIGEST);
    private static final FwIdField FWIDS_LOWERCASE = new FwIdField(HASH_ALG, DIGEST_LOWERCASE);
    private static final String VENDOR_INFO = "VENDOR_INFO";
    private static final String VENDOR_INFO_MASK = "VENDOR_INFO_MASK";

    private final BaseEvidenceBlockToTcbInfoMapper sut = new BaseEvidenceBlockToTcbInfoMapper();

    @Test
    void map_AllEmpty_OnlyIndexIsSetToZero() {
        // given
        final BaseEvidenceBlock block = prepareEmptyBlock();

        // when
        final TcbInfo result = sut.map(block);

        // then
        final Map<TcbInfoField, Object> tcbInfo = result.getTcbInfo();
        Assertions.assertEquals(1, tcbInfo.size());
        Assertions.assertEquals(0, tcbInfo.get(TcbInfoField.INDEX));
    }

    @Test
    void map_AllSet() {
        // given
        final BaseEvidenceBlock block = prepareFilledBlock();

        // when
        final TcbInfo result = sut.map(block);

        // then
        final Map<TcbInfoField, Object> tcbInfo = result.getTcbInfo();
        Assertions.assertEquals(7, tcbInfo.size());
        Assertions.assertEquals(VENDOR, tcbInfo.get(TcbInfoField.VENDOR));
        Assertions.assertEquals(MODEL, tcbInfo.get(TcbInfoField.MODEL));
        Assertions.assertEquals(LAYER_INT, tcbInfo.get(TcbInfoField.LAYER));
        Assertions.assertEquals(INDEX, tcbInfo.get(TcbInfoField.INDEX));
        Assertions.assertEquals(FWIDS, tcbInfo.get(TcbInfoField.FWIDS));
        Assertions.assertEquals(TYPE, tcbInfo.get(TcbInfoField.TYPE));

        final MaskedVendorInfo maskedVendorInfo = (MaskedVendorInfo)tcbInfo.get(TcbInfoField.VENDOR_INFO);
        Assertions.assertEquals(VENDOR_INFO, maskedVendorInfo.getVendorInfo());
        Assertions.assertEquals(VENDOR_INFO_MASK, maskedVendorInfo.getVendorInfoMask());
    }

    @Test
    void map_VerifyFwIdsToUppercase() {
        // given
        final BaseEvidenceBlock block = prepareBlockWithLowercaseDigest();

        // when
        final TcbInfo result = sut.map(block);

        // then
        final Map<TcbInfoField, Object> tcbInfo = result.getTcbInfo();
        final FwIdField fwIds = (FwIdField)tcbInfo.get(TcbInfoField.FWIDS);
        Assertions.assertEquals(DIGEST, fwIds.getDigest());
    }

    private BaseEvidenceBlock prepareEmptyBlock() {
        return new BaseEvidenceBlock();
    }

    private BaseEvidenceBlock prepareFilledBlock() {
        final BaseEvidenceBlock block = new BaseEvidenceBlock();
        block.setVendor(VENDOR);
        block.setModel(MODEL);
        block.setLayer(LAYER);
        block.setIndex(INDEX);
        block.setFwids(List.of(FWIDS));
        block.setVendorInfo(VENDOR_INFO);
        block.setVendorInfoMask(VENDOR_INFO_MASK);
        block.setType(TYPE);
        return block;
    }

    private BaseEvidenceBlock prepareBlockWithLowercaseDigest() {
        final BaseEvidenceBlock block = new BaseEvidenceBlock();
        block.setFwids(List.of(FWIDS_LOWERCASE));
        return block;
    }
}
