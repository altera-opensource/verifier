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

package com.intel.bkp.crypto.crc;

import org.junit.jupiter.api.Test;

import static com.intel.bkp.crypto.crc.Crc32Type.BZIP2;
import static org.junit.jupiter.api.Assertions.assertEquals;

class Crc32RegularTest {

    private static final byte[] REFERENCE_CHECKSUM_DATA = "123456789".getBytes();
    private static final int REFERENCE_CHECKSUM = 0xCBF43926;

    private final Crc32Type sut = Crc32Type.REGULAR;

    @Test
    public void getChecksum_Reference() {
        // when
        final int result = sut.getChecksum(REFERENCE_CHECKSUM_DATA);

        // then
        assertEquals(REFERENCE_CHECKSUM, result);
    }

    @Test
    public void getChecksum_00() {
        // given
        byte[] data = prepareData(0x00);
        final int expected = 0xD202EF8D;

        // when
        final int result = sut.getChecksum(data);

        // then
        assertEquals(expected, result);
    }

    @Test
    public void getChecksum_0000() {
        // given
        byte[] data = prepareData(0x00, 0x00);
        final int expected = 0x41D912FF;

        // when
        final int result = sut.getChecksum(data);

        // then
        assertEquals(expected, result);
    }

    @Test
    public void getChecksum_00000000() {
        // given
        byte[] data = prepareData(0x00, 0x00, 0x00, 0x00);
        final int expected = 0x2144DF1C;

        // when
        final int result = sut.getChecksum(data);

        // then
        assertEquals(expected, result);
    }

    @Test
    public void getChecksum_AF() {
        // given
        byte[] data = prepareData(0xAF);
        final int expected = 0x946B51F4;

        // when
        final int result = sut.getChecksum(data);

        // then
        assertEquals(expected, result);
    }

    @Test
    public void getChecksum_AFAF120A() {
        // given
        byte[] data = prepareData(0xAF, 0xAF, 0x12, 0x0A);
        final int expected = 0x7E4955DF;

        // when
        final int result = sut.getChecksum(data);

        // then
        assertEquals(expected, result);
    }

    @Test
    public void getChecksum_00AA0011() {
        // given
        byte[] data = prepareData(0x00, 0xAA, 0x00, 0x11);
        final int expected = 0xAA1C0A15;

        // when
        final int result = BZIP2.getChecksum(data);

        // then
        assertEquals(expected, result);
    }

    @Test
    public void getChecksum_1100AA00() {
        // given
        byte[] data = prepareData(0x11, 0x00, 0xAA, 0x00);
        final int expected = 0x9D09BB85;

        // when
        final int result = sut.getChecksum(data);

        // then
        assertEquals(expected, result);
    }

    @Test
    public void getChecksum_1111111111111111() {
        // given
        byte[] data = prepareData(0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11);
        final int expected = 0x4DB8ECF5;

        // when
        final int result = sut.getChecksum(data);

        // then
        assertEquals(expected, result);
    }

    @Test
    public void getChecksum_111111111111AA() {
        // given
        byte[] data = prepareData(0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0xAA);
        final int expected = 0x5954B753;

        // when
        final int result = sut.getChecksum(data);

        // then
        assertEquals(expected, result);
    }

    @Test
    public void getChecksum_000000000000FFFF() {
        // given
        byte[] data = prepareData(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF);
        final int expected = 0xDB04CD96;

        // when
        final int result = sut.getChecksum(data);

        // then
        assertEquals(expected, result);
    }

    @Test
    public void getChecksum_FFFF000000000000() {
        // given
        byte[] data = prepareData(0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
        final int expected = 0xD15F93BF;

        // when
        final int result = sut.getChecksum(data);

        // then
        assertEquals(expected, result);
    }

    private byte[] prepareData(int... ints) {
        byte[] bytes = new byte[ints.length];
        int counter = 0;
        for (int i : ints) {
            bytes[counter++] = (byte) i;
        }
        return bytes;
    }
}
