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

package com.intel.bkp.utils;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MaskHelperTest {

    @Test
    void getMask_WithEvenLength_ReturnsFFs() {
        getMask_ReturnsExpected(2, "FF");
    }

    @Test
    void getMask_WithOddLength_ReturnsFFs() {
        getMask_ReturnsExpected(3, "FFF");
    }

    @Test
    void getMask_WithZeroLength_ReturnsEmptyMask() {
        getMask_ReturnsExpected(0, "");
    }

    @Test
    void getMask_WithNegativeLength_ReturnsEmptyMask() {
        getMask_ReturnsExpected(-2, "");
    }

    @Test
    void applyMask_Hex_With4BytesOfEqualLen() {
        applyMask_HexParams_ReturnsExpected("11112222", "11112222", "FFFFFFFF");
    }

    @Test
    void applyMask_Hex_WithValue3ZerosLessThanMask() {
        applyMask_HexParams_ReturnsExpected("12222", "12222000", "FFFFFFFF");
    }

    @Test
    void applyMask_Hex_WithValue2ZerosLessThanMask() {
        applyMask_HexParams_ReturnsExpected("112222", "11222200", "FFFFFFFF");
    }

    @Test
    void applyMask_Hex_WithValue3LargerThanMask_TrimsLast3() {
        applyMask_HexParams_ReturnsExpected("11112222333", "11112222", "FFFFFFFF");
    }

    @Test
    void applyMask_Hex_WithValue2LargerThanMask_TrimsLast2() {
        applyMask_HexParams_ReturnsExpected("1111222233", "11112222", "FFFFFFFF");
    }

    @Test
    void applyMask_Hex_WithOddLengthOfMask_ReturnsOddLength() {
        applyMask_HexParams_ReturnsExpected("1234", "123", "FFF");
    }

    @Test
    void applyMask_Hex_WithOddLengthOfValue_ReturnsEvenLength() {
        applyMask_HexParams_ReturnsExpected("111", "1110", "FFFF");
    }

    @Test
    void applyMask_Hex_WithOddLengthOfValueAndMask_ReturnsOddLength() {
        applyMask_HexParams_ReturnsExpected("111", "11100", "FFFFF");
    }

    @Test
    void applyMask_Hex_WithMaskWithTrailingZeros_PreservesOriginalMaskLength() {
        applyMask_HexParams_ReturnsExpected("111", "1110000", "FFFF000");
    }

    @Test
    void applyMask_Hex_WithMaskWithLeadingZeros_PreservesOriginalMaskLength() {
        applyMask_HexParams_ReturnsExpected("111", "0000000", "000FFFF");
    }

    @Test
    void applyMask_Hex_WithValueWithLeadingZeros_PreservesOriginalMaskLength() {
        applyMask_HexParams_ReturnsExpected("000111", "0001", "FFFF");
    }

    @Test
    void applyMask_ByteArray_WithMaskTheSameLengthAsValue_Success() {
        applyMask_ByteArraysParams_ReturnsExpected("123456", "103056", "F0F0FF");
    }

    @Test
    void applyMask_ByteArray_WithMaskShorterThenValue_Throws() {
        assertThrows(MaskHelper.MismatchedMaskLengthException.class,
            () -> MaskHelper.applyMask(fromHex("0123"), fromHex("FF")));
    }

    @Test
    void applyMask_ByteArray_WithMaskLongerThenValue_Throws() {
        assertThrows(MaskHelper.MismatchedMaskLengthException.class,
            () -> MaskHelper.applyMask(fromHex("0123"), fromHex("FFFFFF")));
    }

    @Test
    void applyMask_ByteArray_WithEmptyMaskAndValue_Success() {
        applyMask_ByteArraysParams_ReturnsExpected("", "", "");
    }

    @Test
    void applyMask_ByteArray_WithMaskWithTrailingZeros_PreservesOriginalMaskLength() {
        applyMask_ByteArraysParams_ReturnsExpected("1111", "1100", "FF00");
    }

    private void getMask_ReturnsExpected(int length, String expectedMask) {
        // when
        final String result = MaskHelper.getMask(length);

        // then
        assertEquals(expectedMask, result);
    }

    @SneakyThrows
    private void applyMask_HexParams_ReturnsExpected(String value, String expectedValue, String mask) {
        // when
        final String result = MaskHelper.applyMask(value, mask);

        // then
        assertEquals(expectedValue, result);
    }

    @SneakyThrows
    private void applyMask_ByteArraysParams_ReturnsExpected(String value, String expectedValue, String mask) {
        // when
        final byte[] result = MaskHelper.applyMask(fromHex(value), fromHex(mask));

        // then
        assertArrayEquals(fromHex(expectedValue), result);
    }

}
