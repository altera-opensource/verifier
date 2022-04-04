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

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toFormattedHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static com.intel.bkp.utils.HexConverter.toLowerCaseHex;

public class HexConverterTest {

    @Test
    public void fromHex_Success() {
        // given
        final byte[] expected = new byte[]{1, 2, 3, 4};

        // when
        final byte[] result = fromHex("01020304");

        // then
        Assertions.assertArrayEquals(expected, result);
    }

    @Test
    public void fromHex_InvalidData_Throws() {
        // when-then
        Assertions.assertThrows(RuntimeException.class, () -> fromHex("XXXXXXXX"));
    }

    @Test
    public void toHex_Integer_Success() {
        // given
        final String expected = "0A";

        // when
        final String result = toHex(10);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void toHex_SingleByte_Success() {
        // given
        final String expected = "0A";

        // when
        final String result = toHex((byte) 0x0a);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void toHex_ByteArray_Success() {
        // given
        final String expected = "010203040A0B0C";

        // when
        final String result = toHex(new byte[]{1, 2, 3, 4, 10, 11, 12});

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void toLowerCaseHex_Success() {
        // given
        final String expected = "010203040a0b0c0d";

        // when
        final String result = toLowerCaseHex(new byte[]{1, 2, 3, 4, 10, 11, 12, 13});

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void toFormattedHex_SingleByte_Success() {
        // given
        final String expected = "0x0A";

        // when
        final String result = toFormattedHex((byte) 0x0a);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void toFormattedHex_Success() {
        // given
        final String expected = "0x01020304 0x0a0b0c0d";

        // when
        final String result = toFormattedHex(new byte[]{1, 2, 3, 4, 10, 11, 12, 13});

        // then
        Assertions.assertEquals(expected, result);
    }
}
