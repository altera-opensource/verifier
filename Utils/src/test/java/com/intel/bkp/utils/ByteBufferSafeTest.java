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

import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Random;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;

public class ByteBufferSafeTest {

    private static final int DATA_SIZE = 4;
    private static final short DATA_SIZE_SHORT = 4;

    @Test
    void wrap_Success() {
        // when
        ByteBufferSafe result = ByteBufferSafe.wrap(new byte[DATA_SIZE]);

        // then
        Assertions.assertNotNull(result);
    }

    @Test
    void order_Success() {
        // when
        ByteBufferSafe buffer = prepareBufferInt();
        ByteOrder order = buffer.order(ByteOrder.LITTLE_ENDIAN).order();

        // then
        Assertions.assertEquals(ByteOrder.LITTLE_ENDIAN, order);
    }

    @Test
    void array_Success() {
        // when
        byte[] data = { 1, 2, 3 };
        ByteBufferSafe buffer = prepareBufferInt(data);

        // then
        Assertions.assertArrayEquals(data, buffer.array());
    }

    @Test
    void getShort_Success() {
        // given
        byte[] bytes = { 0x00, 0x02 };
        short expected = 2;
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteBuffer.allocate(Short.BYTES).put(bytes).array());

        // when
        short result = buffer.getShort();

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getShort_WithOrderBig_Success() {
        // given
        byte[] bytes = { 0x00, 0x02 };
        short expected = 2;
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteBuffer.allocate(Short.BYTES).put(bytes).array());

        // when
        short result = buffer.getShort(ByteOrder.BIG_ENDIAN);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getShort_WithOrderLittle_Success() {
        // given
        byte[] bytes = { 0x00, 0x02 };
        short expected = 512;
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteBuffer.allocate(Short.BYTES).put(bytes).array());

        // when
        short result = buffer.getShort(ByteOrder.LITTLE_ENDIAN);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getInt_Success() {
        // given
        byte[] bytes = { 0x00, 0x00, 0x00, 0x02 };
        int expected = 2;
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteBuffer.allocate(Integer.BYTES).put(bytes).array());

        // when
        int result = buffer.getInt();

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getInt_WithOrderBig_Success() {
        // given
        byte[] bytes = { 0x00, 0x00, 0x00, 0x02 };
        int expected = 2;
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteBuffer.allocate(Integer.BYTES).put(bytes).array());

        // when
        int result = buffer.getInt(ByteOrder.BIG_ENDIAN);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getInt_WithOrderLittle_Success() {
        // given
        byte[] bytes = { 0x00, 0x00, 0x00, 0x02 };
        int expected = 33554432;
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteBuffer.allocate(Integer.BYTES).put(bytes).array());

        // when
        int result = buffer.getInt(ByteOrder.LITTLE_ENDIAN);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getLong_Success() {
        // given
        byte[] bytes = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
        long expected = 2;
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteBuffer.allocate(Long.BYTES).put(bytes).array());

        // when
        long result = buffer.getLong();

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getLong_WithOrderBig_Success() {
        // given
        byte[] bytes = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
        long expected = 2;
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteBuffer.allocate(Long.BYTES).put(bytes).array());

        // when
        long result = buffer.getLong(ByteOrder.BIG_ENDIAN);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getLong_WithOrderLittle_Success() {
        // given
        // Moved 0x02 to 1st position to avoid having to pass here the actual long value
        byte[] bytes = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        long expected = 2;
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteBuffer.allocate(Long.BYTES).put(bytes).array());

        // when
        long result = buffer.getLong(ByteOrder.LITTLE_ENDIAN);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getByte_Success() {
        // given
        byte expected = 2;
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteBuffer.allocate(1).put(expected).array());

        // when
        byte result = buffer.getByte();

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void get_Success() {
        // given
        byte[] data = new byte[DATA_SIZE];
        byte[] expectedData = new byte[] { 1, 2, 3, 4 };
        ByteBufferSafe buffer = prepareBufferInt(expectedData);

        // when
        buffer.get(data);

        // then
        Assertions.assertArrayEquals(expectedData, data);
    }

    @Test
    void getAll_Success() {
        // given
        byte[] data = new byte[DATA_SIZE];
        byte[] expectedData = new byte[] { 1, 2, 3, 4 };
        ByteBufferSafe buffer = prepareBufferInt(expectedData);

        // when
        buffer.getAll(data);

        // then
        Assertions.assertArrayEquals(expectedData, data);
    }

    @Test
    void getAll_TooBigBuffer() {
        // given
        byte[] data = new byte[DATA_SIZE];
        byte[] expectedData = new byte[] { 1, 2, 3, 4, 5, 6 };
        ByteBufferSafe buffer = prepareBufferInt(expectedData);

        Assertions.assertThrows(ByteBufferSafeException.class, () -> {
            buffer.getAll(data);
        });
    }

    @Test
    void getAll_TooSmallBuffer() {
        // given
        byte[] data = new byte[DATA_SIZE];
        byte[] expectedData = new byte[] { 1, 2 };
        ByteBufferSafe buffer = prepareBufferInt(expectedData);

        Assertions.assertThrows(ByteBufferSafeException.class, () -> {
            buffer.getAll(data);
        });
    }

    @Test
    void findFirst_OnlyInteger_Success() {
        // given
        int valueToFind = 5;
        byte[] data = ByteBuffer.allocate(Integer.BYTES).putInt(valueToFind).array();
        ByteBufferSafe buffer = ByteBufferSafe.wrap(data);

        // when
        int result = buffer.findFirst(valueToFind);

        // then
        Assertions.assertEquals(0, result);
        Assertions.assertEquals(0, buffer.position());
    }

    @Test
    void findFirst_OneIntegerDistance_Success() {
        // given
        int valueToFind = 5;
        byte[] data = ByteBuffer.allocate(2 * Integer.BYTES).putInt(0).putInt(valueToFind).array();
        ByteBufferSafe buffer = ByteBufferSafe.wrap(data);

        // when
        int result = buffer.findFirst(valueToFind);

        // then
        Assertions.assertEquals(Integer.BYTES, result);
        Assertions.assertEquals(0, buffer.position());
    }

    @Test
    void findFirst_OneIntegerDistance_ShiftedBy1_Success() {
        // given
        int shiftedBy = 1;
        int valueToFind = 5;
        byte[] data = ByteBuffer.allocate(Integer.BYTES + shiftedBy).put(new byte[] { 1 }).putInt(valueToFind).array();
        ByteBufferSafe buffer = ByteBufferSafe.wrap(data);

        // when
        int result = buffer.findFirst(valueToFind);

        // then
        Assertions.assertEquals(shiftedBy, result);
        Assertions.assertEquals(0, buffer.position());
    }

    @Test
    void findFirst_OneIntegerDistance_ShiftedBy2_Success() {
        // given
        int shiftedBy = 2;
        int valueToFind = 5;
        byte[] data =
            ByteBuffer.allocate(Integer.BYTES + shiftedBy).put(new byte[] { 1, 2 }).putInt(valueToFind).array();
        ByteBufferSafe buffer = ByteBufferSafe.wrap(data);

        // when
        int result = buffer.findFirst(valueToFind);

        // then
        Assertions.assertEquals(shiftedBy, result);
        Assertions.assertEquals(0, buffer.position());
    }

    @Test
    void findFirst_OneIntegerDistance_ShiftedBy3_Success() {
        // given
        int shiftedBy = 3;
        int valueToFind = 5;
        byte[] data = ByteBuffer.allocate(Integer.BYTES + shiftedBy)
            .put(new byte[] { 1, 2, 3 })
            .putInt(valueToFind)
            .array();
        ByteBufferSafe buffer = ByteBufferSafe.wrap(data);

        // when
        int result = buffer.findFirst(valueToFind);

        // then
        Assertions.assertEquals(shiftedBy, result);
        Assertions.assertEquals(0, buffer.position());
    }

    @Test
    void findFirst_NotFound_Throws() {
        // given
        int valueToFind = 5;
        byte[] data = ByteBuffer.allocate(2 * Integer.BYTES).array();
        ByteBufferSafe buffer = ByteBufferSafe.wrap(data);

        // when
        Assertions.assertThrows(ByteBufferSafeException.class, () -> {
            buffer.findFirst(valueToFind);
        });
    }

    @Test
    void position_Success() {
        // given
        ByteBufferSafe buffer = prepareBufferInt();
        int newPosition = DATA_SIZE - 1;

        // when
        buffer.position(newPosition);

        // then
        Assertions.assertEquals(newPosition, buffer.position());
    }

    @Test
    void skip_Success() {
        // given
        ByteBufferSafe buffer = prepareBufferInt();
        int bytesToSkip = 1;
        buffer.position(0);

        // when
        buffer.skip(bytesToSkip);

        // then
        Assertions.assertEquals(bytesToSkip, buffer.position());
    }

    @Test
    void skip_TooFar_Success() {
        // given
        ByteBufferSafe buffer = prepareBufferInt();
        int bytesToSkip = 1000;
        buffer.position(0);

        // when
        Assertions.assertThrows(ByteBufferSafeException.class, () -> {
            buffer.skip(bytesToSkip);
        });
    }

    @Test
    void remaining_Success() {
        // given
        byte[] expectedData = new byte[] { 1, 2, 3, 4 };
        ByteBufferSafe buffer = prepareBufferInt(expectedData);

        // when
        int result = buffer.remaining();

        // then
        Assertions.assertEquals(expectedData.length, result);
    }

    @Test
    void arrayFromShort_Success() {
        // given
        ByteBufferSafe buffer = prepareBufferShort();

        // when
        byte[] result = buffer.arrayFromShort(DATA_SIZE_SHORT);

        // then
        Assertions.assertEquals(DATA_SIZE, result.length);
    }

    @Test
    void arrayFromInt_Success() {
        // given
        ByteBufferSafe buffer = prepareBufferInt();

        // when
        byte[] result = buffer.arrayFromInt(DATA_SIZE);

        // then
        Assertions.assertEquals(DATA_SIZE, result.length);
    }

    @Test
    void arrayFromNextInt_Success() {
        // given
        ByteBufferSafe buffer = prepareBufferInt();

        // when
        byte[] result = buffer.arrayFromNextInt();

        // then
        Assertions.assertEquals(DATA_SIZE, result.length);
    }

    @Test
    void arrayFromNextInt_WithOrderLittle_Success() {
        // given
        ByteBufferSafe buffer = prepareBufferInt(ByteOrder.LITTLE_ENDIAN);

        // when
        byte[] result = buffer.arrayFromNextInt(ByteOrder.LITTLE_ENDIAN);

        // then
        Assertions.assertEquals(DATA_SIZE, result.length);
    }

    @Test
    void arrayFromNextLong_WithIntValue_Success() {
        // given
        ByteBufferSafe buffer = prepareBufferLong();

        // when
        byte[] result = buffer.arrayFromNextLong();

        // then
        Assertions.assertEquals(DATA_SIZE, result.length);
    }

    @Test
    void arrayFromNextLong_WithOrderLittle_WithIntValue_Success() {
        // given
        ByteBufferSafe buffer = prepareBufferLong(ByteOrder.LITTLE_ENDIAN);

        // when
        byte[] result = buffer.arrayFromNextLong(ByteOrder.LITTLE_ENDIAN);

        // then
        Assertions.assertEquals(DATA_SIZE, result.length);
    }

    @Test
    void arrayFromRemaining_WithNoOffset_Success() {
        // when
        ByteBufferSafe buffer = prepareBufferInt();
        byte[] result = buffer.arrayFromRemaining();

        // then
        Assertions.assertEquals(DATA_SIZE + Integer.BYTES, result.length);
    }

    @Test
    void arrayFromRemaining_WithSmallOffset_Success() {
        // given
        ByteBufferSafe buffer = prepareBufferInt();
        int offsetFromEnd = 2;

        // when
        byte[] result = buffer.arrayFromRemaining(offsetFromEnd);

        // then
        Assertions.assertEquals(DATA_SIZE + Integer.BYTES - offsetFromEnd, result.length);
    }

    @Test
    void verifyIfRemainingHasLen_WithInt_Success() {
        //given
        ByteBufferSafe buffer = prepareBufferInt();

        // when
        buffer.verifyIfRemainingHasLen(DATA_SIZE);
    }

    @Test
    void verifyIfRemainingHasLen_WithLong_Success() {
        //given
        ByteBufferSafe buffer = prepareBufferInt();

        // when
        buffer.verifyIfRemainingHasLen((long)DATA_SIZE);
    }

    @Test
    void verifyIfBufferHasPosition_Success() {
        //given
        ByteBufferSafe buffer = prepareBufferInt();

        // when
        buffer.verifyIfBufferHasPosition(DATA_SIZE - 1);
    }

    @Test
    void verifyIfRemainingHasLen_WithInt_NegativeValue_Throws() {
        //given
        ByteBufferSafe buffer = prepareBufferInt();

        Assertions.assertThrows(ByteBufferSafeException.class, () -> {
            buffer.verifyIfRemainingHasLen(-2);
        });
    }

    @Test
    void verifyIfRemainingHasLen_WithInt_TooBigValue_Throws() {
        //given
        ByteBufferSafe buffer = prepareBufferInt();

        Assertions.assertThrows(ByteBufferSafeException.class, () -> {
            buffer.verifyIfRemainingHasLen(1000);
        });
    }

    @Test
    void verifyIfRemainingHasLen_WithLong_MaxIntValue_Throws() {
        //given
        ByteBufferSafe buffer = prepareBufferInt();

        Assertions.assertThrows(ByteBufferSafeException.class, () -> {
            buffer.verifyIfRemainingHasLen(Long.MAX_VALUE);
        });
    }

    @Test
    void verifyIfRemainingHasLen_WithLong_NegativeValue_Throws() {
        // given
        ByteBufferSafe buffer = prepareBufferInt();

        Assertions.assertThrows(ByteBufferSafeException.class, () -> buffer.verifyIfRemainingHasLen(-2));
    }

    @Test
    void verifyIfRemainingHasLen_WithLong_TooBigValue_Throws() {
        Assertions.assertThrows(ByteBufferSafeException.class, () -> {
            //given
            ByteBufferSafe buffer = prepareBufferInt();

            // when
            buffer.verifyIfRemainingHasLen(1000);
        });
    }

    @Test
    void verifyIfBufferHasPosition_NegativeValue_Throws() {
        //given
        ByteBufferSafe buffer = prepareBufferInt();

        Assertions.assertThrows(ByteBufferSafeException.class, () -> buffer.verifyIfBufferHasPosition(-2));
    }

    @Test
    void verifyIfBufferHasPosition_TooBigValue_Throws() {
        //given
        ByteBufferSafe buffer = prepareBufferInt();

        Assertions.assertThrows(ByteBufferSafeException.class,
            () -> buffer.verifyIfBufferHasPosition(DATA_SIZE + Integer.BYTES + 1));
    }

    @Test
    void getRemaining_Success() {
        // given
        byte[] testData = generateDeviceId();

        // when
        byte[] remaining = ByteBufferSafe.wrap(testData).skipInteger().getRemaining();

        // then
        Assertions.assertEquals(testData.length - Integer.BYTES, remaining.length);
    }

    @Test
    void mark_Success() {
        // given
        byte[] testData = fromHex("17629317000020006C69676100007865");
        int testDataLen = 16;
        ByteBufferSafe bufferSafe = ByteBufferSafe.wrap(testData);

        bufferSafe.skipInteger();
        bufferSafe.mark(); // Mark position for reset
        bufferSafe.skipInteger().skipInteger();
        Assertions.assertEquals(testDataLen - (Integer.BYTES * 3), bufferSafe.remaining());
        bufferSafe.reset(); // Reset to marked position
        Assertions.assertEquals(testDataLen - Integer.BYTES, bufferSafe.remaining());
        bufferSafe.rewind(); // Reset to initial position
        Assertions.assertEquals(testDataLen, bufferSafe.remaining());
    }

    private ByteBufferSafe prepareBufferShort() {
        byte[] data = ByteBuffer.allocate(Short.BYTES + DATA_SIZE_SHORT).putShort(DATA_SIZE_SHORT).array();
        return ByteBufferSafe.wrap(data);
    }

    private ByteBufferSafe prepareBufferInt() {
        byte[] data = ByteBuffer.allocate(Integer.BYTES + DATA_SIZE).putInt(DATA_SIZE).array();
        return ByteBufferSafe.wrap(data);
    }

    private ByteBufferSafe prepareBufferInt(ByteOrder byteOrder) {
        byte[] data = ByteBuffer.allocate(Integer.BYTES + DATA_SIZE).order(byteOrder).putInt(DATA_SIZE).array();
        return ByteBufferSafe.wrap(data);
    }

    private ByteBufferSafe prepareBufferInt(byte[] data) {
        return ByteBufferSafe.wrap(data);
    }

    private ByteBufferSafe prepareBufferLong() {
        byte[] data = ByteBuffer.allocate(Long.BYTES + DATA_SIZE).putLong(DATA_SIZE).array();
        return ByteBufferSafe.wrap(data);
    }

    private ByteBufferSafe prepareBufferLong(ByteOrder byteOrder) {
        byte[] data = ByteBuffer.allocate(Long.BYTES + DATA_SIZE).order(byteOrder).putLong(DATA_SIZE).array();
        return ByteBufferSafe.wrap(data);
    }

    public static byte[] generateDeviceId() {
        byte[] deviceIdBytes = new byte[Long.BYTES];
        new Random().nextBytes(deviceIdBytes);
        System.out.println(toHex(deviceIdBytes));
        return deviceIdBytes;
    }
}
