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

import static com.intel.bkp.utils.ByteConverter.toBytes;
import static com.intel.bkp.utils.ByteConverter.toInt;
import static com.intel.bkp.utils.HexConverter.toHex;

class ByteConverterTest {

    @Test
    void toBytes_Success() {
        // given
        int data = 1;
        String expected = "00000001";

        // when
        byte[] result = toBytes(data);

        // then
        Assertions.assertEquals(expected, toHex(result));
    }

    @Test
    void toBytes_WithLargerInt_Success() {
        // given
        int data = 10111111;
        String expected = "009A4887";

        // when
        byte[] result = toBytes(data);

        // then
        Assertions.assertEquals(expected, toHex(result));
    }

    @Test
    void toIntegerBytes_WithSingleBytePackedToInteger_Success() {
        // given
        byte data = (byte) 0x01;
        String expected = "01000000";

        // when
        byte[] result = ByteConverter.toIntegerBytes(data);

        // then
        Assertions.assertEquals(expected, toHex(result));
    }

    @Test
    void toInt_BinaryIntToInt_Success() {
        // given
        byte[] data = new byte[]{0x08, 0x64, 0x03, 0x44};
        int expected = 140772164;

        // when
        int result = toInt(data);

        // then
        Assertions.assertEquals(expected, result);
    }
}
