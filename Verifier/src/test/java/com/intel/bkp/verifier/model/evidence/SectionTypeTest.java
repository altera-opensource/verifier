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

import com.intel.bkp.verifier.exceptions.SectionTypeException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SectionTypeTest {

    @Test
    void fromByte_SupportedSection0() {
        // given
        final byte value = 0;

        // when
        final SectionType result = SectionType.from(value);

        // then
        assertEquals(SectionType.RESERVED, result);
    }

    @Test
    void fromByte_SupportedSection1() {
        // given
        final byte value = 1;

        // when
        final SectionType result = SectionType.from(value);

        // then
        assertEquals(SectionType.DEVICE_STATE, result);
    }

    @Test
    void fromByte_SupportedSection12() {
        // given
        final byte value = 12;

        // when
        final SectionType result = SectionType.from(value);

        // then
        assertEquals(SectionType.LAYER_2_BASE_DESIGN, result);
    }

    @Test
    void fromByte_UnsupportedSection_Throws() {
        // given
        final byte value = 13;

        // when-then
        final IllegalArgumentException thrown =
            Assertions.assertThrows(SectionTypeException.class, () -> SectionType.from(value));
        Assertions.assertEquals(String.format(SectionType.UNSUPPORTED_SECTION_TYPE, value), thrown.getMessage());
    }

    @Test
    void fromBlock_BlockWithNullTypeAndLayer_Throws() {
        // given
        final BaseEvidenceBlock block = new BaseEvidenceBlock();

        // when-then
        final IllegalArgumentException thrown =
            Assertions.assertThrows(SectionTypeException.class, () -> SectionType.from(block));
        Assertions.assertEquals(SectionType.FAILED_TO_DETERMINE_SECTION_TYPE, thrown.getMessage());
    }

    @Test
    void fromBlock_BlockWithType() {
        // given
        final BaseEvidenceBlock block = new BaseEvidenceBlock();
        block.setType(String.valueOf(SectionType.IO.getValue()));

        // when
        final SectionType result = SectionType.from(block);

        // then
        assertEquals(SectionType.IO, result);
    }

    @Test
    void fromBlock_BlockWithTypeNotByte_ThrowsDueToTypeNotBeingByteValue() {
        // given
        final BaseEvidenceBlock block = new BaseEvidenceBlock();
        block.setType("A.A");

        // when-then
        final IllegalArgumentException thrown =
            Assertions.assertThrows(SectionTypeException.class, () -> SectionType.from(block));
        Assertions.assertEquals(SectionType.TYPE_IDENTIFIER_MUST_BE_BYTE_VALUE, thrown.getMessage());
    }

    @Test
    void from_BlockWithLayer0() {
        // given
        final BaseEvidenceBlock block = new BaseEvidenceBlock();
        block.setLayer("0");

        // when
        final SectionType result = SectionType.from(block);

        // then
        assertEquals(SectionType.LAYER_0_FW_ROM_EXT, result);
    }

    @Test
    void from_BlockWithLayer1() {
        // given
        final BaseEvidenceBlock block = new BaseEvidenceBlock();
        block.setLayer("1");

        // when
        final SectionType result = SectionType.from(block);

        // then
        assertEquals(SectionType.LAYER_1_FW_CMF, result);
    }

    @Test
    void from_BlockWithLayer2() {
        // given
        final BaseEvidenceBlock block = new BaseEvidenceBlock();
        block.setLayer("2");

        // when
        final SectionType result = SectionType.from(block);

        // then
        assertEquals(SectionType.LAYER_2_BASE_DESIGN, result);
    }

    @Test
    void from_BlockWithLayer3_ThrowsDueToUnsupportedLayer() {
        // given
        final BaseEvidenceBlock block = new BaseEvidenceBlock();
        block.setLayer("3");

        // when-then
        final IllegalArgumentException thrown =
            Assertions.assertThrows(SectionTypeException.class, () -> SectionType.from(block));
        Assertions.assertEquals(SectionType.LAYER_CAN_ONLY_HAVE_VALUES, thrown.getMessage());
    }

    @Test
    void from_BlockWithLayerMinusOne_ThrowsDueToUnsupportedLayer() {
        // given
        final BaseEvidenceBlock block = new BaseEvidenceBlock();
        block.setLayer("-1");

        // when-then
        final IllegalArgumentException thrown =
            Assertions.assertThrows(SectionTypeException.class, () -> SectionType.from(block));
        Assertions.assertEquals(SectionType.LAYER_CAN_ONLY_HAVE_VALUES, thrown.getMessage());
    }

    @Test
    void from_BlockWithLayerNotInteger_ThrowsDueToLayerNotBeingIntegerValue() {
        // given
        final BaseEvidenceBlock block = new BaseEvidenceBlock();
        block.setLayer("A");

        // when-then
        final IllegalArgumentException thrown =
            Assertions.assertThrows(SectionTypeException.class, () -> SectionType.from(block));
        Assertions.assertEquals(SectionType.LAYER_MUST_BE_INTEGER_VALUE, thrown.getMessage());
    }

    @Test
    void fromTypeLayer() {
        // given
        String type = "1.1.1.2";

        // when
        final SectionType result = SectionType.fromTypeLayer(type, null);

        // then
        assertEquals(SectionType.IO, result);
    }

    @Test
    void fromTypeLayer_TypeIsNull() {
        // given
        Integer layer = 1;

        // when
        final SectionType result = SectionType.fromTypeLayer(null, layer);

        // then
        assertEquals(SectionType.LAYER_1_FW_CMF, result);
    }
}
