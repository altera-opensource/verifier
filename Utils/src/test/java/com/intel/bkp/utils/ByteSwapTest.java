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

import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.utils.ByteSwapOrder.B2L;
import static com.intel.bkp.utils.ByteSwapOrder.L2B;

class ByteSwapTest {

    @Test
    void getSwappedArray_WithShort_BigToLittle_Success() {
        // given
        short data = 1;
        byte[] expected = new byte[]{1, 0};

        // when
        byte[] result = ByteSwap.getSwappedArray(data, B2L);

        // then
        Assertions.assertArrayEquals(expected, result);
    }

    @Test
    void getSwappedArray_WithShort_LittleToBig_Success() {
        // given
        short data = 1;
        byte[] expected = new byte[]{0, 1};

        // when
        byte[] result = ByteSwap.getSwappedArray(data, L2B);

        // then
        Assertions.assertArrayEquals(expected, result);
    }

    @Test
    void getSwappedArray_WithInteger_BigToLittle_Success() {
        // given
        int data = 1;
        byte[] expected = new byte[]{1, 0, 0, 0};

        // when
        byte[] result = ByteSwap.getSwappedArray(data, B2L);

        // then
        Assertions.assertArrayEquals(expected, result);
    }

    @Test
    void getSwappedArray_WithInteger_LittleToBig_Success() {
        // given
        int data = 1;
        byte[] expected = new byte[]{0, 0, 0, 1};

        // when
        byte[] result = ByteSwap.getSwappedArray(data, L2B);

        // then
        Assertions.assertArrayEquals(expected, result);
    }

    @Test
    void getSwappedArray_WithLong_BigToLittle_Success() {
        // given
        long data = 1;
        byte[] expected = new byte[]{1, 0, 0, 0, 0, 0, 0, 0};

        // when
        byte[] result = ByteSwap.getSwappedArray(data, B2L);

        // then
        Assertions.assertArrayEquals(expected, result);
    }

    @Test
    void getSwappedArray_WithLong_LittleToBig_Success() {
        // given
        long data = 1;
        byte[] expected = new byte[]{0, 0, 0, 0, 0, 0, 0, 1};

        // when
        byte[] result = ByteSwap.getSwappedArray(data, L2B);

        // then
        Assertions.assertArrayEquals(expected, result);
    }

    @Test
    void getSwappedShort_BigToLittle_Success() {
        // given
        short data = 1;
        short expected = 256;

        // when
        short result = ByteSwap.getSwappedShort(data, B2L);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getSwappedShort_LittleToBig_Success() {
        // given
        short data = 256;
        short expected = 1;

        // when
        short result = ByteSwap.getSwappedShort(data, L2B);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getSwappedShort_ConvertArrayByShort_BigToLittle_Success() {
        // given
        byte[] data = new byte[]{0x00, 0x01};
        short expected = 256;

        // when
        short result = ByteSwap.getSwappedShort(data, B2L);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getSwappedShort_ConvertArrayByShort_LittleToBig_Success() {
        // given
        byte[] data = new byte[]{0x01, 0x00};
        short expected = 1;

        // when
        short result = ByteSwap.getSwappedShort(data, L2B);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getSwappedInt_BigToLittle_Success() {
        // given
        int data = 1;
        int expected = 16777216;

        // when
        int result = ByteSwap.getSwappedInt(data, B2L);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getSwappedInt_LittleToBig_Success() {
        // given
        int data = 16777216;
        int expected = 1;

        // when
        int result = ByteSwap.getSwappedInt(data, L2B);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getSwappedArrayByInt_Success() {
        // given
        byte[] data = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] expected = new byte[]{4, 3, 2, 1, 8, 7, 6, 5};

        // when
        byte[] result = ByteSwap.getSwappedArrayByInt(data, B2L);

        // then
        Assertions.assertArrayEquals(expected, result);
    }

    @Test
    void getSwappedArrayByInt_BigToLittle_Success() {
        // given
        byte[] arrayToSwap = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        byte[] expectedSwappedArray = new byte[]{0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04};
        // when
        final byte[] destination = ByteSwap.getSwappedArrayByInt(arrayToSwap, B2L);

        // then
        Assertions.assertArrayEquals(expectedSwappedArray, destination);
    }

    @Test
    void getSwappedArrayByInt_LittleToBig_Success() {
        // given
        byte[] arrayToSwap = new byte[]{0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04};
        byte[] expectedSwappedArray = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        // when
        final byte[] destination = ByteSwap.getSwappedArrayByInt(arrayToSwap, L2B);

        // then
        Assertions.assertArrayEquals(expectedSwappedArray, destination);
    }

    @Test
    void getSwappedArrayByLong_Success() {
        // given
        byte[] data = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] expected = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};

        // when
        byte[] result = ByteSwap.getSwappedArrayByLong(data, B2L);

        // then
        Assertions.assertArrayEquals(expected, result);
    }

    @Test
    void verifyIfArrayIsMultipleOfValue_IsMultiple_Success() {
        // given
        byte[] data = new byte[8];

        // when
        Assertions.assertDoesNotThrow(() -> {
            ByteSwap.getSwappedArrayByInt(data, B2L);
        });
    }

    @Test
    void verifyIfArrayIsMultipleOfValue_IsNotMultiple_Throws() {
        // given
        byte[] data = new byte[9];

        Assertions.assertThrows(ByteBufferSafeException.class, () -> ByteSwap.getSwappedArrayByInt(data, B2L));
    }
}
