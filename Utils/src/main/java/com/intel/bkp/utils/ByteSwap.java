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
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.nio.ByteBuffer;

/**
 * This class is intended to change data order.
 */

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ByteSwap {

    private static final String ARRAY_LENGTH_NOT_MULTIPLE_OF = "Destination array length is %d, "
        + "but should be a multiple of %d.";

    public static byte[] getSwappedArray(short source, ByteSwapOrder byteSwapOrder) {
        ByteBuffer sourceBuffer = getBufferWithShort(source, byteSwapOrder);
        return ByteBuffer.allocate(Short.BYTES)
            .order(byteSwapOrder.getDestOrder()).putShort(sourceBuffer.getShort()).array();
    }

    public static byte[] getSwappedArray(int source, ByteSwapOrder byteSwapOrder) {
        ByteBuffer sourceBuffer = getBufferWithInteger(source, byteSwapOrder);
        return ByteBuffer.allocate(Integer.BYTES)
            .order(byteSwapOrder.getDestOrder()).putInt(sourceBuffer.getInt()).array();
    }

    public static byte[] getSwappedArray(long source, ByteSwapOrder byteSwapOrder) {
        ByteBuffer sourceBuffer = getBufferWithLong(source, byteSwapOrder);
        return ByteBuffer.allocate(Long.BYTES)
            .order(byteSwapOrder.getDestOrder()).putLong(sourceBuffer.getLong()).array();
    }

    /**
     * Reverses integer value.
     */
    public static int getSwappedInt(int source, ByteSwapOrder byteSwapOrder) {
        ByteBuffer buffer = getBufferWithInteger(source, byteSwapOrder);
        return buffer.order(byteSwapOrder.getDestOrder()).getInt();
    }

    /**
     * Reverses short value.
     */
    public static short getSwappedShort(short source, ByteSwapOrder byteSwapOrder) {
        ByteBuffer buffer = getBufferWithShort(source, byteSwapOrder);
        return buffer.order(byteSwapOrder.getDestOrder()).getShort();
    }

    public static short getSwappedShort(byte[] source, ByteSwapOrder byteSwapOrder) {
        verifyIfArrayIsMultipleOfValue(source, Short.BYTES);
        final short sourceShort = ByteBuffer.wrap(source).getShort();
        return getSwappedShort(sourceShort, byteSwapOrder);
    }

    /**
     * Reverts chunks (4 bytes) of data.
     */
    public static byte[] getSwappedArrayByInt(byte[] source, ByteSwapOrder byteSwapOrder) {
        verifyIfArrayIsMultipleOfValue(source, Integer.BYTES);

        ByteBuffer sourceBuffer = ByteBuffer.wrap(source).order(byteSwapOrder.getSourceOrder());
        ByteBuffer tempBuffer = ByteBuffer.allocate(source.length).order(byteSwapOrder.getDestOrder());
        while (sourceBuffer.remaining() >= Integer.BYTES) {
            tempBuffer.putInt(sourceBuffer.getInt());
        }
        return tempBuffer.array();
    }

    /**
     * Reverts chunks (8 bytes) of data.
     */
    public static byte[] getSwappedArrayByLong(byte[] source, ByteSwapOrder byteSwapOrder) {
        verifyIfArrayIsMultipleOfValue(source, Long.BYTES);

        ByteBuffer sourceBuffer = ByteBuffer.wrap(source).order(byteSwapOrder.getSourceOrder());
        ByteBuffer tempBuffer = ByteBuffer.allocate(source.length).order(byteSwapOrder.getDestOrder());
        while (sourceBuffer.remaining() >= Long.BYTES) {
            tempBuffer.putLong(sourceBuffer.getLong());
        }
        return tempBuffer.array();
    }

    private static ByteBuffer getBufferWithShort(short source, ByteSwapOrder byteSwapOrder) {
        return ByteBuffer.allocate(Short.BYTES)
            .order(byteSwapOrder.getSourceOrder()).putShort(source).rewind();
    }

    private static ByteBuffer getBufferWithInteger(int source, ByteSwapOrder byteSwapOrder) {
        return ByteBuffer.allocate(Integer.BYTES)
            .order(byteSwapOrder.getSourceOrder()).putInt(source).rewind();
    }

    private static ByteBuffer getBufferWithLong(long source, ByteSwapOrder byteSwapOrder) {
        return ByteBuffer.allocate(Long.BYTES)
            .order(byteSwapOrder.getSourceOrder()).putLong(source).rewind();
    }

    private static void verifyIfArrayIsMultipleOfValue(byte[] array, int value) {
        if (array.length % value != 0) {
            throw new ByteBufferSafeException(
                String.format(ARRAY_LENGTH_NOT_MULTIPLE_OF, array.length, value)
            );
        }
    }
}
