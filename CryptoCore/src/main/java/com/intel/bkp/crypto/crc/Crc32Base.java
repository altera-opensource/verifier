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


/**
 * This is implementation of CRC32 algorithm using NORMAL FORM (shift left) with FORWARD POLYNOMINAL (0x04C11DB7).
 * Code is written based on C++ implementation from: https://github.com/Michaelangel007/crc32#formulaic-crc
 * CRC for tests are calculated using: https://crccalc.com
 */
public abstract class Crc32Base {

    protected static final String EMPTY_DATA_ERROR_MSG = "Data cannot be null or empty";
    protected static final int INIT_CRC = -1;
    private static final int POLY = 0x04C11DB7;

    abstract int perform(int crc, byte[] data);

    public int getChecksum(byte[] data) {
        if (data == null || 0 == data.length) {
            throw new IllegalArgumentException(EMPTY_DATA_ERROR_MSG);
        }
        return perform(INIT_CRC, data);
    }

    protected int getChecksumInternal(int crc) {
        // read 8 bits one at a time
        for (int i = 0; i < Byte.SIZE; i++) {
            if (crc < 0) {
                crc <<= 1;
                crc ^= POLY;
            } else {
                crc <<= 1;
            }
        }
        return crc;
    }
}
