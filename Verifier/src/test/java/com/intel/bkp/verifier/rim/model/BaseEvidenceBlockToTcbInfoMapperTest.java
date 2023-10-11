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

package com.intel.bkp.verifier.rim.model;

import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoConstants;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfo;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BaseEvidenceBlockToTcbInfoMapperTest {

    private static final String TYPE = "TYPE";
    private static final String VENDOR = "VENDOR";
    private static final String VENDOR_MIXED_LETTER_SIZE = "VeNdOr";
    private static final String MODEL = "MODEL";
    private static final String MODEL_MIXED_LETTER_SIZE = "MoDeL";
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
    void map_AllEmpty() {
        // given
        final BaseEvidenceBlock block = prepareEmptyBlock();
        final List<TcbInfoField> expectedFields = List.of();

        // when
        final TcbInfo result = sut.map(block);

        // then
        verifyFields(result, expectedFields);
    }

    @Test
    void map_AllSet() {
        // given
        final BaseEvidenceBlock block = prepareFilledBlock();
        final var expectedFields = List.of(TcbInfoField.VENDOR, TcbInfoField.MODEL, TcbInfoField.LAYER,
            TcbInfoField.INDEX, TcbInfoField.FWIDS, TcbInfoField.TYPE, TcbInfoField.VENDOR_INFO);

        // when
        final TcbInfo result = sut.map(block);

        // then
        verifyFields(result, expectedFields);

        assertEquals(VENDOR, result.get(TcbInfoField.VENDOR).get());
        assertEquals(MODEL, result.get(TcbInfoField.MODEL).get());
        assertEquals(LAYER_INT, result.get(TcbInfoField.LAYER).get());
        assertEquals(INDEX, result.get(TcbInfoField.INDEX).get());
        assertEquals(FWIDS, result.get(TcbInfoField.FWIDS).get());
        assertEquals(TYPE, result.get(TcbInfoField.TYPE).get());

        final MaskedVendorInfo maskedVendorInfo = (MaskedVendorInfo) result.get(TcbInfoField.VENDOR_INFO).get();
        assertEquals(VENDOR_INFO, maskedVendorInfo.getVendorInfo());
        assertEquals(VENDOR_INFO_MASK, maskedVendorInfo.getVendorInfoMask());
    }

    @Test
    void map_VendorInfoButNoMask_SetsDefaultVendorInfoMask() {
        // given
        final BaseEvidenceBlock block = prepareBlockWithVendorInfoButNoMask();
        final var expectedFields = List.of(TcbInfoField.VENDOR_INFO);

        // when
        final TcbInfo result = sut.map(block);

        // then
        verifyFields(result, expectedFields);

        final MaskedVendorInfo maskedVendorInfo = (MaskedVendorInfo) result.get(TcbInfoField.VENDOR_INFO).get();
        assertEquals(VENDOR_INFO, maskedVendorInfo.getVendorInfo());
        final String vendorInfoMask = maskedVendorInfo.getVendorInfoMask();
        assertEquals(VENDOR_INFO.length(), vendorInfoMask.length());
        assertTrue(vendorInfoMask.matches("^F+$"));
    }

    @Test
    void map_UntypedMeasurementWithModelAndIntelVendor_SetsIndexWithZero() {
        // given
        final BaseEvidenceBlock block = prepareBlockWithIntelVendorAndModel();
        final var expectedFields = List.of(TcbInfoField.VENDOR, TcbInfoField.MODEL, TcbInfoField.INDEX);

        // when
        final TcbInfo result = sut.map(block);

        // then
        verifyFields(result, expectedFields);

        assertEquals(TcbInfoConstants.INDEX, result.get(TcbInfoField.INDEX).get());
    }

    @Test
    void map_VerifyFwIdsToUppercase() {
        // given
        final BaseEvidenceBlock block = prepareBlockWithLowercaseDigest();

        // when
        final TcbInfo result = sut.map(block);

        // then
        final Optional<FwIdField> fwIds = result.get(TcbInfoField.FWIDS);
        assertEquals(DIGEST, fwIds.get().getDigest());
    }

    @Test
    void map_VerifyVendorAndModelPreserveLetterSize() {
        // given
        final BaseEvidenceBlock block = prepareBlockWithVendorAndModelWithMixedLetterSize();

        // when
        final TcbInfo result = sut.map(block);

        // then
        assertEquals(VENDOR_MIXED_LETTER_SIZE, result.get(TcbInfoField.VENDOR).get());
        assertEquals(MODEL_MIXED_LETTER_SIZE, result.get(TcbInfoField.MODEL).get());
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

    private BaseEvidenceBlock prepareBlockWithVendorAndModelWithMixedLetterSize() {
        final BaseEvidenceBlock block = new BaseEvidenceBlock();
        block.setVendor(VENDOR_MIXED_LETTER_SIZE);
        block.setModel(MODEL_MIXED_LETTER_SIZE);
        return block;
    }

    private BaseEvidenceBlock prepareBlockWithIntelVendorAndModel() {
        final BaseEvidenceBlock block = new BaseEvidenceBlock();
        block.setVendor(TcbInfoConstants.VENDOR);
        block.setModel(MODEL);
        return block;
    }

    private BaseEvidenceBlock prepareBlockWithVendorInfoButNoMask() {
        final BaseEvidenceBlock block = new BaseEvidenceBlock();
        block.setVendorInfo(VENDOR_INFO);
        return block;
    }

    private void verifyFields(TcbInfo tcbInfo, List<TcbInfoField> expectedFields) {
        final var unexpectedFields = Arrays.stream(TcbInfoField.values()).filter(f -> !expectedFields.contains(f));

        expectedFields.forEach(field -> assertTrue(tcbInfo.get(field).isPresent()));
        unexpectedFields.forEach(field -> assertTrue(tcbInfo.get(field).isEmpty()));
    }
}
