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
 * It is compliant with format CRC-32 algorithm which reverses both input DATA and calculated CRC.
 * Written based on this repo: https://github.com/Michaelangel007/crc32/blob/master/src/crc32.h#L52
 * This is how SmartNIC team is calculating CRC32 under Manifest.
 */
public class Crc32Regular extends Crc32Base {

    @Override
    int perform(int crc, byte[] data) {
        for (byte b : data) {
            crc = (crc ^ (reverseBits(b) << 24));
            crc = getChecksumInternal(crc);
        }
        return reverseBits32(~crc);
    }

    private int reverseBits(byte x) {
        return (reverseBits32(x) >> 24) & 0xFF;
    }

    private int reverseBits32(int x) {
        int bits = 0;
        int mask = x;

        for (int i = 0; i < Integer.SIZE; i++) {
            bits <<= 1;
            if ((mask & 1) != 0) {
                bits |= 1;
            }
            mask >>= 1;
        }

        return bits;
    }
}
