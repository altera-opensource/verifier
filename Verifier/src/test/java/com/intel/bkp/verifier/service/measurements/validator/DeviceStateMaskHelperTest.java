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

package com.intel.bkp.verifier.service.measurements.validator;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class DeviceStateMaskHelperTest {

    @Test
    void getMask_WithBlank_ReturnsFFs() {
        // given
        final String value = "11112222";
        final String mask = " ";
        final String expectedMask = "FFFFFFFF";

        // when
        final String result = DeviceStateMaskHelper.getMask(value, mask);

        // then
        Assertions.assertEquals(expectedMask, result);
    }

    @Test
    void getMask_WithNull_ReturnsFFs() {
        // given
        final String value = "11112222";
        String mask = null;
        final String expectedMask = "FFFFFFFF";

        // when
        final String result = DeviceStateMaskHelper.getMask(value, mask);

        // then
        Assertions.assertEquals(expectedMask, result);
    }

    @Test
    void getMask_WithBlankAndValueShorterThanInteger_ReturnsPaddedFFs() {
        // given
        final String value = "222";
        final String mask = " ";
        final String expectedMask = "00000FFF";

        // when
        final String result = DeviceStateMaskHelper.getMask(value, mask);

        // then
        Assertions.assertEquals(expectedMask, result);
    }

    @Test
    void getMask_WithNotBlank_ReturnsPadded() {
        // given
        final String value = "222";
        final String mask = "FFF";
        final String expectedMask = "00000FFF";

        // when
        final String result = DeviceStateMaskHelper.getMask(value, mask);

        // then
        Assertions.assertEquals(expectedMask, result);
    }

    @Test
    void getMask_WithNotBlankAndLenEqualToInteger_ReturnsSame() {
        // given
        final String value = "222";
        final String mask = "00000FFF";
        final String expectedMask = "00000FFF";

        // when
        final String result = DeviceStateMaskHelper.getMask(value, mask);

        // then
        Assertions.assertEquals(expectedMask, result);
    }

    @Test
    void applyMask_With4BytesOfEqualLen() {
        // given
        final String value = "11112222";
        final String expectedValue = "11112222";
        final String mask = "FFFFFFFF";

        // when
        final String result = DeviceStateMaskHelper.applyMask(value, mask);

        // then
        Assertions.assertEquals(expectedValue, result);
    }

    @Test
    void applyMask_WithValue3ZerosLessThanMask() {
        // given
        final String value = "12222";
        final String expectedValue = "00012222";
        final String mask = "FFFFFFFF";

        // when
        final String result = DeviceStateMaskHelper.applyMask(value, mask);

        // then
        Assertions.assertEquals(expectedValue, result);
    }

    @Test
    void applyMask_WithValue2ZerosLessThanMask() {
        // given
        final String value = "112222";
        final String expectedValue = "00112222";
        final String mask = "FFFFFFFF";

        // when
        final String result = DeviceStateMaskHelper.applyMask(value, mask);

        // then
        Assertions.assertEquals(expectedValue, result);
    }

    @Test
    void applyMask_WithValue3LargerThanMask_TrimsFirst3() {
        // given
        final String value = "11112222333";
        final String expectedValue = "12222333";
        final String mask = "FFFFFFFF";

        // when
        final String result = DeviceStateMaskHelper.applyMask(value, mask);

        // then
        Assertions.assertEquals(expectedValue, result);
    }

    @Test
    void applyMask_WithValue2LargerThanMask_TrimsFirst2() {
        // given
        final String value = "1111222233";
        final String expectedValue = "11222233";
        final String mask = "FFFFFFFF";

        // when
        final String result = DeviceStateMaskHelper.applyMask(value, mask);

        // then
        Assertions.assertEquals(expectedValue, result);
    }
}
