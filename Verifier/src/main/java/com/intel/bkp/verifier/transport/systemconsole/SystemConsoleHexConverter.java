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

package com.intel.bkp.verifier.transport.systemconsole;

import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import com.intel.bkp.utils.HexConverter;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static com.intel.bkp.utils.HexConverter.toHex;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SystemConsoleHexConverter {

    private static final int WORD_SIZE = 4;

    public static String toString(byte[] array) {
        if (array.length % WORD_SIZE != 0) {
            throw new IllegalArgumentException("Array length must be multiple of 4.");
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < array.length; i += WORD_SIZE) {
            byte[] subarray = Arrays.copyOfRange(array, i, i + WORD_SIZE);
            byte[] subarraySwapped = swapArrayDueToWordFormat(subarray);
            sb
                .append("0x")
                .append(toHex(subarraySwapped))
                .append(i + WORD_SIZE == array.length ? "" : " ");
        }

        return sb.toString();
    }

    public static byte[] fromString(String result) {
        if (result.isBlank()) {
            return new byte[0];
        }

        List<byte[]> byteArrays = Arrays.stream(result.split("0x"))
            .map(String::trim)
            .filter(s -> !s.isBlank())
            .map(HexConverter::fromHex)
            .map(SystemConsoleHexConverter::swapArrayDueToWordFormat)
            .collect(Collectors.toList());

        if (byteArrays.stream().anyMatch(bytes -> bytes.length != WORD_SIZE)) {
            throw new IllegalArgumentException("String must contain 4-byte words separated with 0x and a whitespace.");
        }

        return joinArrays(byteArrays);
    }

    private static byte[] joinArrays(List<byte[]> byteArrays) {
        ByteBuffer buffer = ByteBuffer.allocate(getTotalNumberOfBytes(byteArrays));
        byteArrays.forEach(buffer::put);
        return buffer.array();
    }

    private static byte[] swapArrayDueToWordFormat(byte[] array) {
        return ByteSwap.getSwappedArrayByInt(array, ByteSwapOrder.CONVERT);
    }

    private static int getTotalNumberOfBytes(List<byte[]> byteArrays) {
        return byteArrays.stream().mapToInt(value -> value.length).sum();
    }
}
