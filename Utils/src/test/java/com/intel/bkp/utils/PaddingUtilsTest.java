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

import org.junit.jupiter.api.Test;

import java.util.function.BiFunction;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class PaddingUtilsTest {

    private static final byte[] ARRAY = new byte[]{1, 2, 3};

    @Test
    void padRight_SmallerSize_AddsPaddingAtTheEnd() {
        padRight_ReturnsExpected("1234", 3, "123400");
    }

    @Test
    void padRight_GreaterSize_DoesNothing() {
        padRight_ReturnsExpected("1234", 1, "1234");
    }

    @Test
    void padLeft_SmallerSize_AddsPadding() {
        padLeft_ReturnsExpected("112233", 4, "00112233");
    }

    @Test
    void padLeft_GreaterSize_DoesNothing() {
        padLeft_ReturnsExpected("112233", 2, "112233");
    }

    @Test
    void trimLeft_GreaterSize_RemovesPadding() {
        trimLeft_ReturnsExpected("112233", 2, "2233");
    }

    @Test
    void trimLeft_SmallerSize_DoesNothing() {
        trimLeft_ReturnsExpected("112233", 5, "112233");
    }

    @Test
    void trimRight_GreaterSize_TrimsEnding() {
        trimRight_ReturnsExpected("112233", 2, "1122");
    }

    @Test
    void trimRight_SmallerSize_DoesNothing() {
        trimRight_ReturnsExpected("112233", 4, "112233");
    }

    @Test
    void alignLeft_SmallerSize_AlignsToExpected() {
        alignLeft("112233", 4, "00112233");
    }

    @Test
    void alignLeft_GreaterSize_AlignsToExpected() {
        alignLeft("112233", 2, "2233");
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
        assertEquals(expected, result);
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
        assertEquals(expected, result);
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
        assertEquals(expected, result);
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
        assertEquals(expected, result);
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
        assertEquals(expected, result);
    }

    @Test
    void getPaddingPacked_WithDifferentLengths_Success() {
        // given
        final int paddingLength = 4;

        // when
        final byte[] result = PaddingUtils.getPaddingPacked(ARRAY, paddingLength + ARRAY.length);

        // then
        assertEquals(paddingLength, result.length);
    }

    @Test
    void getPaddingPacked_WithSameLengths_Success() {
        // when
        final byte[] result = PaddingUtils.getPaddingPacked(ARRAY, ARRAY.length);

        // then
        assertEquals(0, result.length);
    }

    private void padRight_ReturnsExpected(String hex, int lengthInBytes, String expectedHex) {
        method_ReturnsExpected(PaddingUtils::padRight, hex, lengthInBytes, expectedHex);
    }

    private void padLeft_ReturnsExpected(String hex, int lengthInBytes, String expectedHex) {
        method_ReturnsExpected(PaddingUtils::padLeft, hex, lengthInBytes, expectedHex);
    }

    private void trimRight_ReturnsExpected(String hex, int lengthInBytes, String expectedHex) {
        method_ReturnsExpected(PaddingUtils::trimRight, hex, lengthInBytes, expectedHex);
    }

    private void trimLeft_ReturnsExpected(String hex, int lengthInBytes, String expectedHex) {
        method_ReturnsExpected(PaddingUtils::trimLeft, hex, lengthInBytes, expectedHex);
    }

    private void alignLeft(String hex, int lengthInBytes, String expectedHex) {
        method_ReturnsExpected(PaddingUtils::alignLeft, hex, lengthInBytes, expectedHex);
    }

    private void method_ReturnsExpected(BiFunction<byte[], Integer, byte[]> method,
                                        String hex, int lengthInBytes, String expectedHex) {
        // when
        final byte[] result = method.apply(fromHex(hex), lengthInBytes);

        // then
        assertEquals(expectedHex, toHex(result));
    }
}
