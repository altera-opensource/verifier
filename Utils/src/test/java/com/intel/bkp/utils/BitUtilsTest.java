/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2022 Intel Corporation. All Rights Reserved.
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

import org.junit.jupiter.api.Test;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

class BitUtilsTest {

    @Test
    void isSet_AllAmpty_ReturnsFalse() {
        isSet_ReturnsExpected(0, "00", false);
    }

    @Test
    void isSet_FirstBitSet_ReturnsTrue() {
        isSet_ReturnsExpected(0, "01", true);
    }

    @Test
    void isSet_SecondBitSet_ReturnsTrue() {
        isSet_ReturnsExpected(1, "02", true);
    }

    @Test
    void isSet_ThirdBitSet_ReturnsTrue() {
        // when
        isSet_ReturnsExpected(2, "04", true);
    }

    @Test
    void isSet_LastBitSet_ReturnsTrue() {
        // when
        isSet_ReturnsExpected(7, "80", true);
    }

    @Test
    void isSet_BitIndexExceedsBitMaskSize_ReturnsFalse() {
        isSet_ReturnsExpected(8, "FF", false);
    }

    @Test
    void and_SingleBytes_Success() {
        and_ReturnsExpected("12", "FF", "12");
    }

    @Test
    void and_EqualLength_Success() {
        and_ReturnsExpected("1234", "FF0F", "1204");
    }

    @Test
    void and_DifferentLength_Success() {
        and_ReturnsExpected("123456", "FF0F", "1204");
    }

    @Test
    void countSetBits_EmptyArray_Returns0() {
        countSetBits_ReturnsExpected(new byte[]{}, 0);
    }

    @Test
    void countSetBits_Value0() {
        countSetBits_ReturnsExpected(new byte[]{0}, 0);
    }

    @Test
    void countSetBits_Value1() {
        countSetBits_ReturnsExpected(new byte[]{1}, 1);
    }

    @Test
    void countSetBits_ValueF() {
        countSetBits_ReturnsExpected(new byte[]{0xF}, 4);
    }

    @Test
    void countSetBits_Value7F() {
        countSetBits_ReturnsExpected(new byte[]{0x7F}, 7);
    }

    @Test
    void countSetBits_ValueMinus1() {
        countSetBits_ReturnsExpected(new byte[]{-1}, 8);
    }

    @Test
    void countSetBits_Value1_1() {
        countSetBits_ReturnsExpected(new byte[]{1, 1}, 2);
    }

    @Test
    void countSetBits_ValueF_F() {
        countSetBits_ReturnsExpected(new byte[]{0xF, 0xF}, 8);
    }

    @Test
    void countSetBits_ValueOfFiveBytes() {
        countSetBits_ReturnsExpected(new byte[]{1, 1, 1, 1, 1}, 5);
    }

    private void isSet_ReturnsExpected(int bitIndex, String hex, boolean expected) {
        // when
        final boolean result = BitUtils.isSet(bitIndex, fromHex(hex));

        // then
        assertEquals(expected, result);
    }

    private void and_ReturnsExpected(String a, String b, String expected) {
        // when
        final byte[] result = BitUtils.and(fromHex(a), fromHex(b));

        // then
        assertEquals(expected, toHex(result));
    }

    private static void countSetBits_ReturnsExpected(byte[] bitMask, int expectedBitsSet) {
        // when
        final int result = BitUtils.countSetBits(bitMask);

        // then
        assertEquals(expectedBitsSet, result);
    }
}
