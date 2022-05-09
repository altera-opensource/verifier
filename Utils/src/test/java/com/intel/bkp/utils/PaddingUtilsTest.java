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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class PaddingUtilsTest {

    private static final byte[] ARRAY_LEN_3 = new byte[]{1, 2, 3};
    private static final byte[] EXPECTED_ARRAY_FROM_3 = new byte[]{0, 0, 0, 1, 2, 3};
    private static final byte[] ARRAY_LEN_7 = new byte[]{1, 2, 3, 4, 5, 6, 7};
    private static final byte[] EXPECTED_ARRAY_FROM_7 = new byte[]{2, 3, 4, 5, 6, 7};
    private static final int EXPECTED_LEN = 6;

    @Test
    void addPadding_SmallerSize_AddsPadding() {
        // when
        final byte[] result = PaddingUtils.addPadding(ARRAY_LEN_3, EXPECTED_LEN);

        // then
        Assertions.assertEquals(EXPECTED_LEN, result.length);
        Assertions.assertArrayEquals(EXPECTED_ARRAY_FROM_3, result);
    }

    @Test
    void addPadding_GreaterSize_DoesNothing() {
        // when
        final byte[] result = PaddingUtils.addPadding(ARRAY_LEN_7, EXPECTED_LEN);

        // then
        Assertions.assertEquals(ARRAY_LEN_7.length, result.length);
        Assertions.assertArrayEquals(ARRAY_LEN_7, result);
    }

    @Test
    void removePadding_GreaterSize_RemovesPadding() {
        // when
        final byte[] result = PaddingUtils.removePadding(ARRAY_LEN_7, EXPECTED_LEN);

        // then
        Assertions.assertEquals(EXPECTED_LEN, result.length);
        Assertions.assertArrayEquals(EXPECTED_ARRAY_FROM_7, result);
    }

    @Test
    void removePadding_SmallerSize_DoesNothing() {
        // when
        final byte[] result = PaddingUtils.removePadding(ARRAY_LEN_3, EXPECTED_LEN);

        // then
        Assertions.assertEquals(ARRAY_LEN_3.length, result.length);
        Assertions.assertArrayEquals(ARRAY_LEN_3, result);
    }

    @Test
    void alignTo_SmallerSize_AlignsToExpected() {
        // when
        final byte[] result = PaddingUtils.alignTo(ARRAY_LEN_3, EXPECTED_LEN);

        // then
        Assertions.assertEquals(EXPECTED_LEN, result.length);
        Assertions.assertArrayEquals(EXPECTED_ARRAY_FROM_3, result);
    }

    @Test
    void alignTo_GreaterSize_AlignsToExpected() {
        // when
        final byte[] result = PaddingUtils.alignTo(ARRAY_LEN_7, EXPECTED_LEN);

        // then
        Assertions.assertEquals(EXPECTED_LEN, result.length);
        Assertions.assertArrayEquals(EXPECTED_ARRAY_FROM_7, result);
    }

    @Test
    void getPaddingLengthPacked_Return0() {
        // given
        int packSize = 32;
        byte[] array = new byte[32];
        int expected = 0;

        // when
        int result = PaddingUtils.getPaddingLengthPacked(array, packSize);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getPaddingLengthPacked_Return1() {
        // given
        int packSize = 32;
        byte[] array = new byte[31];
        int expected = 1;

        // when
        int result = PaddingUtils.getPaddingLengthPacked(array, packSize);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getPaddingLengthPacked_Return31() {
        // given
        int packSize = 32;
        byte[] array = new byte[1];
        int expected = 31;

        // when
        int result = PaddingUtils.getPaddingLengthPacked(array, packSize);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getPaddingLengthPacked_BiggerThanPackSize_Return31() {
        // given
        int packSize = 32;
        byte[] array = new byte[33];
        int expected = 31;

        // when
        int result = PaddingUtils.getPaddingLengthPacked(array, packSize);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getPaddingLengthPacked_MultipleOfPackSize_Return0() {
        // given
        int packSize = 32;
        byte[] array = new byte[64];
        int expected = 0;

        // when
        int result = PaddingUtils.getPaddingLengthPacked(array, packSize);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getPaddingPacked_WithDifferentLengths_Success() {
        // when
        final byte[] result = PaddingUtils.getPaddingPacked(ARRAY_LEN_3, EXPECTED_LEN);

        // then
        Assertions.assertEquals(EXPECTED_LEN - ARRAY_LEN_3.length, result.length);
    }

    @Test
    void getPaddingPacked_WithSameLengths_Success() {
        // when
        final byte[] result = PaddingUtils.getPaddingPacked(ARRAY_LEN_3, 3);

        // then
        Assertions.assertEquals(0, result.length);
    }
}
