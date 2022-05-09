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

class ConverterHelperTest {

    @Test
    void convertTime_Success() {
        // given
        String time = "2021-04-22 13:45:59";
        String format = "yyyy-MM-dd HH:mm:ss";
        Long expected = 1619099159000L;

        // when
        Long result = ConverterHelper.convertTime(time, format);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void convertTime_TimeIsNull() {
        // given
        String time = null;
        String format = "yyyy-MM-dd HH:mm:ss";

        // when
        Long result = ConverterHelper.convertTime(time, format);

        // then
        Assertions.assertNull(result);
    }

    @Test
    void convertTime_TimeDoesNotMatchFormat() {
        // given
        String time = "13:45:59 2021-04-22";
        String mismatchedFormat = "yyyy-MM-dd HH:mm:ss";

        // when
        Long result = ConverterHelper.convertTime(time, mismatchedFormat);

        // then
        Assertions.assertNull(result);
    }

    @Test
    void convertTime_InvalidFormat() {
        // given
        String time = "13:45:59 2021-04-22";
        String invalidFormat = "yyyy-mm-DD blabla HH:mm:ss";

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> ConverterHelper.convertTime(time, invalidFormat));
    }
}
