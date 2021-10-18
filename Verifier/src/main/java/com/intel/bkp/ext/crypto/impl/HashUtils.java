/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.ext.crypto.impl;

import com.intel.bkp.ext.utils.ByteBufferSafe;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.Arrays;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class HashUtils {

    public static String generateSha256Fingerprint(byte[] data) {
        return DigestUtils.sha256Hex(data);
    }

    /**
     * Get Most Significant bytes for SHA 384. It returns last 4 bytes from hash in reverse order
     *
     * @param data - input data
     * @return int
     */
    public static int get32MSBitsForSha384(byte[] data) {
        byte[] bytes = DigestUtils.sha384(data);
        ByteBufferSafe wrap = ByteBufferSafe.wrap(bytes);
        wrap.position(wrap.remaining() - Integer.BYTES);
        int mostSignificantInt = wrap.getInt();
        return Integer.reverseBytes(mostSignificantInt);
    }

    /**
     * Get Most Significant bytes for SHA 384. It returns first 20 bytes from hash
     *
     * @param data - input data
     * @return int
     */
    public static byte[] get20MSBytesForSha384(byte[] data) {
        return getMSBytesForSha384(data, 20);
    }

    private static byte[] getMSBytesForSha384(byte[] data, int numberOfMSBytes) {
        byte[] bytes = DigestUtils.sha384(data);
        return Arrays.copyOfRange(bytes, 0, numberOfMSBytes);
    }
}
