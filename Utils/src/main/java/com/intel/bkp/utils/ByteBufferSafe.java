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
import lombok.AllArgsConstructor;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * This class is intended to wrap all parsing calls to ByteBuffer and verify if requested action is available. E.g. The
 * user has array of 2 bytes, but wants to get Integer (getInt()) out of it. In this case error will be thrown. If the
 * user would have an array of let's say 6 bytes, the getInt() operation completes as usual.
 */

@AllArgsConstructor
public class ByteBufferSafe {

    private static final String BUFFER_REMAINING_LENGTH_INVALID = "Buffer remaining length is %d, but requested %d.";
    private static final String BUFFER_REMAINING_LENGTH_NOT_EQUAL = "Buffer remaining length is %d, "
        + "but should be equal to %d.";
    private static final String BUFFER_NEW_POSITION_INVALID = "Buffer has size of %d, but requested position %d.";
    private static final String BUFFER_REQUESTED_VALUE_NOT_FOUND = "Requested value %d not found.";

    private ByteBuffer buffer;

    public static ByteBufferSafe wrap(byte[] array) {
        return new ByteBufferSafe(ByteBuffer.wrap(array));
    }

    public ByteBufferSafe order(ByteOrder bo) {
        buffer.order(bo);
        return this;
    }

    public ByteOrder order() {
        return buffer.order();
    }

    public byte[] array() {
        return buffer.array();
    }

    public short getShort() {
        verifyIfRemainingHasLen(Short.BYTES);
        return buffer.getShort();
    }

    public short getShort(ByteOrder byteOrder) {
        ByteOrder currentOrder = saveCurrentByteOrder();
        buffer.order(byteOrder);
        short value = getShort();
        restoreSavedByteOrder(currentOrder);
        return value;
    }

    public int getInt() {
        verifyIfRemainingHasLen(Integer.BYTES);
        return buffer.getInt();
    }

    public int getInt(ByteOrder byteOrder) {
        ByteOrder currentOrder = saveCurrentByteOrder();
        buffer.order(byteOrder);
        int value = getInt();
        restoreSavedByteOrder(currentOrder);
        return value;
    }

    public long getLong() {
        verifyIfRemainingHasLen(Long.BYTES);
        return buffer.getLong();
    }

    public long getLong(ByteOrder byteOrder) {
        ByteOrder currentOrder = saveCurrentByteOrder();
        buffer.order(byteOrder);
        long value = getLong();
        restoreSavedByteOrder(currentOrder);
        return value;
    }

    public byte getByte() {
        verifyIfRemainingHasLen(1);
        return buffer.get();
    }

    public ByteBufferSafe get(byte[] dst) {
        verifyIfRemainingHasLen(dst.length);
        buffer.get(dst);
        return this;
    }

    private ByteOrder saveCurrentByteOrder() {
        return buffer.order();
    }

    private void restoreSavedByteOrder(ByteOrder currentOrder) {
        buffer.order(currentOrder);
    }

    /**
     * Gets all remaining bytes from buffer and puts into array if remaining bytes size and destination array size are
     * equal. Throws exception otherwise.
     *
     * @param dst Destination Byte array which should be filled with data from buffer.
     *
     * @return ByteBufferSafe object.
     */
    public ByteBufferSafe getAll(byte[] dst) {
        verifyIfRemainingIsEqual(dst.length);
        buffer.get(dst);
        return this;
    }

    public ByteBufferSafe skip(int numberOfBytes) {
        int newPosition = buffer.position() + numberOfBytes;
        verifyIfBufferHasPosition(newPosition);
        buffer.position(newPosition);
        return this;
    }

    public ByteBufferSafe skipInteger() {
        this.skip(Integer.BYTES);
        return this;
    }

    /**
     * Returns number of bytes to next requested integer value.
     *
     * @param valueToFind Integer value to find within the buffer.
     *
     * @return Number of skipped bytes. Throws exception if value is not found.
     */
    public int findFirst(int valueToFind) {
        int oldPosition = buffer.position();
        for (int i = 0; i < Integer.BYTES; i++) {
            // Shift by one byte every time and repeat search
            buffer.position(oldPosition + i);

            while (buffer.remaining() >= Integer.BYTES) {
                if (buffer.getInt() == valueToFind) {
                    int numberOfBytes = buffer.position() - oldPosition - Integer.BYTES;
                    buffer.position(oldPosition);
                    return numberOfBytes;
                }
            }
        }

        throw new ByteBufferSafeException(
            String.format(BUFFER_REQUESTED_VALUE_NOT_FOUND, valueToFind));
    }

    public ByteBufferSafe position(int newPosition) {
        verifyIfBufferHasPosition(newPosition);
        buffer.position(newPosition);
        return this;
    }

    public int position() {
        return buffer.position();
    }

    public int remaining() {
        return buffer.remaining();
    }

    public byte[] arrayFromShort(short len) {
        verifyIfRemainingHasLen(len);
        return new byte[len];
    }

    public byte[] arrayFromInt(int len) {
        verifyIfRemainingHasLen(len);
        return new byte[len];
    }

    public byte[] arrayFromNextInt() {
        int len = this.getInt();
        verifyIfRemainingHasLen(len);
        return new byte[len];
    }

    public byte[] arrayFromNextInt(ByteOrder byteOrder) {
        int len = this.getInt(byteOrder);
        verifyIfRemainingHasLen(len);
        return new byte[len];
    }

    public byte[] arrayFromNextLong() {
        long lenLong = this.getLong();
        verifyIfRemainingHasLen(lenLong);
        int len = (int)lenLong;
        return new byte[len];
    }

    public byte[] arrayFromNextLong(ByteOrder byteOrder) {
        long lenLong = this.getLong(byteOrder);
        verifyIfRemainingHasLen(lenLong);
        int len = (int)lenLong;
        return new byte[len];
    }

    public byte[] arrayFromRemaining() {
        int len = buffer.remaining();
        return new byte[len];
    }

    public byte[] arrayFromRemaining(int offsetFromEnd) {
        verifyIfRemainingHasLen(offsetFromEnd);
        int len = buffer.remaining() - offsetFromEnd;
        return new byte[len];
    }

    void verifyIfRemainingIsEqual(int value) {
        if (buffer.remaining() != value) {
            throw new ByteBufferSafeException(
                String.format(BUFFER_REMAINING_LENGTH_NOT_EQUAL, buffer.remaining(), value)
            );
        }
    }

    void verifyIfRemainingHasLen(int value) {
        if (value < 0 || buffer.remaining() < value) {
            throw new ByteBufferSafeException(
                String.format(BUFFER_REMAINING_LENGTH_INVALID, buffer.remaining(), value)
            );
        }
    }

    void verifyIfRemainingHasLen(long value) {
        if (value >= Integer.MAX_VALUE || value < 0L || buffer.remaining() < value) {
            throw new ByteBufferSafeException(
                String.format(BUFFER_REMAINING_LENGTH_INVALID, buffer.remaining(), value)
            );
        }
    }

    void verifyIfBufferHasPosition(int value) {
        if (value < 0 || buffer.limit() < value) {
            throw new ByteBufferSafeException(
                String.format(BUFFER_NEW_POSITION_INVALID, buffer.limit(), value)
            );
        }
    }

    public ByteBufferSafe mark() {
        buffer.mark();
        return this;
    }

    public void reset() {
        buffer.reset();
    }

    public void rewind() {
        buffer.rewind();
    }

    public byte[] getRemaining() {
        final byte[] remaining = arrayFromRemaining();
        buffer.get(remaining);
        return remaining;
    }
}
