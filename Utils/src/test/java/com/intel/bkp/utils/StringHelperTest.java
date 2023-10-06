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
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StringHelperTest {

    @Test
    void toFirstLetterCapitalized_MultipleChars_Success() {
        toFirstLetterCapitalized_ReturnsExpected("agiLEX", "Agilex");
    }

    @Test
    void toFirstLetterCapitalized_SingleChar_Success() {
        toFirstLetterCapitalized_ReturnsExpected("a", "A");
    }

    @Test
    void toFirstLetterCapitalized_EmptyString_ReturnsEmptyString() {
        toFirstLetterCapitalized_ReturnsExpected("", "");
    }

    @Test
    void toFirstLetterCapitalized_Null_ReturnsNull() {
        toFirstLetterCapitalized_ReturnsExpected(null, null);
    }

    @Test
    void zeroExtendEndingToEvenLength_OddLength_AddsZeroAtTheEnd() {
        zeroExtendEndingToEvenLength_ReturnsExpected("abc", "abc0");
    }

    @Test
    void zeroExtendEndingToEvenLength_EvenLength_ReturnsTheSameString() {
        zeroExtendEndingToEvenLength_ReturnsExpected("ab", "ab");
    }

    @Test
    void zeroExtendEndingToEvenLength_EmptyString_ReturnsEmptyString() {
        zeroExtendEndingToEvenLength_ReturnsExpected("", "");
    }

    @Test
    void zeroExtendEndingToEvenLength_Null_ReturnsNull() {
        zeroExtendEndingToEvenLength_ReturnsExpected(null, null);
    }

    @Test
    void zeroExtendEnding_ShorterString_ReturnsExtendedToDesiredLength() {
        zeroExtendEnding_ReturnsExpected("abc", 5, "abc00");
    }

    @Test
    void zeroExtendEnding_LongerString_ReturnsTheSameString() {
        zeroExtendEnding_ReturnsExpected("abcdef", 5, "abcdef");
    }

    @Test
    void zeroExtendEnding_EmptyString_ReturnsStringWithAllZeros() {
        zeroExtendEnding_ReturnsExpected("", 5, "00000");
    }

    @Test
    void zeroExtendEnding_Null_ReturnsNull() {
        zeroExtendEnding_ReturnsExpected(null, 5, null);
    }

    @Test
    void truncateEnding_ShorterString_ReturnsTheSameString() {
        truncateEnding_ReturnsExpected("abc", 5, "abc");
    }

    @Test
    void truncateEnding_LongerString_ReturnsTruncatedToDesiredLength() {
        truncateEnding_ReturnsExpected("abcdef", 5, "abcde");
    }

    @Test
    void truncateEnding_EmptyString_ReturnsEmptyString() {
        truncateEnding_ReturnsExpected("", 5, "");
    }

    @Test
    void truncateEnding_Null_ReturnsNull() {
        truncateEnding_ReturnsExpected(null, 5, null);
    }

    private void toFirstLetterCapitalized_ReturnsExpected(String str, String expectedResult) {
        function_ReturnsExpected(StringHelper::toFirstLetterCapitalized, str, expectedResult);
    }

    private void zeroExtendEndingToEvenLength_ReturnsExpected(String str, String expectedResult) {
        function_ReturnsExpected(StringHelper::zeroExtendEndingToEvenLength, str, expectedResult);
    }

    private void zeroExtendEnding_ReturnsExpected(String str, Integer desiredLength, String expectedResult) {
        function_ReturnsExpected(StringHelper::zeroExtendEnding, str, desiredLength, expectedResult);
    }

    private void truncateEnding_ReturnsExpected(String str, Integer desiredLength, String expectedResult) {
        function_ReturnsExpected(StringHelper::truncateEnding, str, desiredLength, expectedResult);
    }

    private void function_ReturnsExpected(Function<String, String> function, String str, String expectedResult) {
        // when-then
        assertEquals(expectedResult, function.apply(str));
    }

    private void function_ReturnsExpected(BiFunction<String, Integer, String> function, String str,
                                          Integer desiredLength, String expectedResult) {
        // when-then
        assertEquals(expectedResult, function.apply(str, desiredLength));
    }
}
