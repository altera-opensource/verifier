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

package com.intel.bkp.crypto;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

public class CRC32NormalTest {

    @Test
    public void getChecksum_00() {
        // given
        byte[] data = prepareData(0x00);
        String expected = "B1F7404B";

        // when
        String result = getChecksumAsHex(data);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void getChecksum_0000() {
        // given
        byte[] data = prepareData(0x00, 0x00);
        String expected = "FF489B82";

        // when
        String result = getChecksumAsHex(data);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void getChecksum_00000000() {
        // given
        byte[] data = prepareData(0x00, 0x00, 0x00, 0x00);
        String expected = "38FB2284";

        // when
        String result = getChecksumAsHex(data);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void getChecksum_AF() {
        // given
        byte[] data = prepareData(0xAF);
        String expected = "7897ABF8";

        // when
        String result = getChecksumAsHex(data);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void getChecksum_AFAF120A() {
        // given
        byte[] data = prepareData(0xAF, 0xAF, 0x12, 0x0A);
        String expected = "D2381C0E";

        // when
        String result = getChecksumAsHex(data);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void getChecksum_00AA0011() {
        // given
        byte[] data = prepareData(0x00, 0xAA, 0x00, 0x11);
        String expected = "AA1C0A15";

        // when
        String result = getChecksumAsHex(data);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void getChecksum_1100AA00() {
        // given
        byte[] data = prepareData(0x11, 0x00, 0xAA, 0x00);
        String expected = "9B17A673";

        // when
        String result = getChecksumAsHex(data);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void getChecksum_1111111111111111() {
        // given
        byte[] data = prepareData(0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11);
        String expected = "13A2415F";

        // when
        String result = getChecksumAsHex(data);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void getChecksum_111111111111AA() {
        // given
        byte[] data = prepareData(0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0xAA);
        String expected = "9BAE0E5E";

        // when
        String result = getChecksumAsHex(data);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void getChecksum_000000000000FFFF() {
        // given
        byte[] data = prepareData(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF);
        String expected = "69B320DB";

        // when
        String result = getChecksumAsHex(data);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    public void getChecksum_FFFF000000000000() {
        // given
        byte[] data = prepareData(0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
        String expected = "FDC9FA8B";

        // when
        String result = getChecksumAsHex(data);

        // then
        Assertions.assertEquals(expected, result);
    }

    private byte[] prepareData(int... ints) {
        byte[] bytes = new byte[ints.length];
        int counter = 0;
        for (int i : ints) {
            bytes[counter++] = (byte)i;
        }
        return bytes;
    }

    private static String getChecksumAsHex(byte[] data) {
        int crc = CRC32Normal.getChecksum(data);
        return Hex.toHexString(ByteBuffer.allocate(Integer.BYTES).putInt(crc).array()).toUpperCase();
    }
}
