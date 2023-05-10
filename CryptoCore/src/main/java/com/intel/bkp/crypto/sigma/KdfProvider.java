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

package com.intel.bkp.crypto.sigma;

import com.intel.bkp.crypto.exceptions.HMacProviderException;
import com.intel.bkp.crypto.hmac.HMacKdfProviderImpl;
import lombok.Getter;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class KdfProvider {

    private static final byte STANDARD_SEPARATOR = 0;
    private static final int RESERVED = 0;

    public static final int PMK_OUTPUT_KEY_LEN = 48; // bytes
    public static final int SEK_SMK_OUTPUT_KEY_LEN = 32; // bytes

    private static final int COUNTER_LEN = 4; // bytes
    private static final int LABEL_LEN = 27;  // bytes
    private static final int SEPARATOR_LEN = 1; // bytes
    private static final int CONTEXT_LEN = 16; // bytes
    private static final int RESERVED_LEN = 4; // bytes
    private static final int OUTPUT_KEY_SIZE_LEN = 4; // bytes

    private static final int COUNTER = 1;

    private static final ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;

    private static int getDataSize() {
        return COUNTER_LEN + LABEL_LEN + SEPARATOR_LEN + CONTEXT_LEN + RESERVED_LEN + OUTPUT_KEY_SIZE_LEN;
    }

    private static ByteBuffer getBuffer(KdfDetails detail, int outputSize) {
        return ByteBuffer.allocate(getDataSize())
            .order(byteOrder)
            .putInt(COUNTER)
            .put(detail.getLabel())
            .put(STANDARD_SEPARATOR)
            .put(KdfDetails.CONTEXT.getLabel())
            .putInt(RESERVED)
            .putInt(outputSize * 8); // must be in bits
    }

    public static byte[] derivePMK(byte[] masterSecret) throws HMacProviderException {
        return deriveInternal(masterSecret, getBuffer(KdfDetails.PROTOCOL_MAC, PMK_OUTPUT_KEY_LEN),
            PMK_OUTPUT_KEY_LEN);
    }

    public static byte[] deriveSEK(byte[] masterSecret) throws HMacProviderException {
        return deriveInternal(masterSecret, getBuffer(KdfDetails.SESSION_ENC, SEK_SMK_OUTPUT_KEY_LEN),
            SEK_SMK_OUTPUT_KEY_LEN);
    }

    public static byte[] deriveSMK(byte[] masterSecret) throws HMacProviderException {
        return deriveInternal(masterSecret, getBuffer(KdfDetails.SESSION_MAC, SEK_SMK_OUTPUT_KEY_LEN),
            SEK_SMK_OUTPUT_KEY_LEN);
    }

    private static byte[] deriveInternal(byte[] masterSecret, ByteBuffer byteBuffer, int outputSize)
        throws HMacProviderException {
        final byte[] hashedBytes = new HMacKdfProviderImpl(masterSecret).getHash(byteBuffer);
        return Arrays.copyOfRange(hashedBytes, 0, outputSize);
    }

    public enum KdfDetails {

        SESSION_ENC("SESSION ENC", LABEL_LEN),
        SESSION_MAC("SESSION MAC", LABEL_LEN),
        PROTOCOL_MAC("PROTOCOL MAC", LABEL_LEN),
        CONTEXT("PSG-SIGMA", CONTEXT_LEN);

        @Getter
        private final int len;

        private final String label;

        KdfDetails(String label, int len) {
            this.label = label;
            this.len = len;
        }

        public byte[] getLabel() {
            return ByteBuffer.allocate(this.getLen())
                .put(this.label.getBytes(StandardCharsets.US_ASCII))
                .array();
        }
    }
}
