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

package com.intel.bkp.test;

import com.intel.bkp.core.helper.ManifestUniqueId;
import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;

import java.nio.ByteBuffer;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import static com.intel.bkp.utils.HexConverter.toHex;

public class RandomUtils {

    public static String generateDeviceIdHex() {
        return toHex(generateDeviceId());
    }

    public static ManifestUniqueId generateUniqueId() {
        return ManifestUniqueId.from(generateDeviceIdHex(), getRandomFamily().getAsInteger());
    }

    public static Family getRandomFamily() {
        final var families = Family.values();
        return families[ThreadLocalRandom.current().nextInt(families.length)];
    }

    public static byte[] generateDeviceId() {
        return generateRandomBytes(Long.BYTES);
    }

    public static String generateRandomHex(int bytesSize) {
        return toHex(generateRandomBytes(bytesSize));
    }

    public static byte[] generateRandomBytes(int size) {
        final byte[] bytes = new byte[size];
        ThreadLocalRandom.current().nextBytes(bytes);
        return bytes;
    }

    public static byte[] generateRandom256Bytes() {
        final int size = 256;
        final int number = size / Integer.BYTES;
        final ByteBuffer byteBuffer = ByteBuffer.allocate(size);

        for (int i = 0; i < number; i++) {
            int randomInt = generateRandomInteger();
            byteBuffer.putInt(randomInt);
        }
        return byteBuffer.array();
    }

    public static int generateRandomInteger() {
        return ThreadLocalRandom.current().nextInt();
    }

    public static Long generateRandomLong() {
        return ThreadLocalRandom.current().nextLong();
    }

    public static String generateUuidString() {
        return UUID.randomUUID().toString();
    }

    public static byte[] asBytesSwapped(int value) {
        return ByteSwap.getSwappedArray(value, ByteSwapOrder.CONVERT);
    }
}
