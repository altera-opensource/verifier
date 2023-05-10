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

package com.intel.bkp.crypto.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.utils.HexConverter.fromHex;

class HashUtilsTest {

    @Test
    void generateFingerprint_Success() {
        // given
        byte[] input = new byte[]{1, 2, 3, 4};
        String exp = "5a667d62430a8c253ebae433333904dc6e1d41dcdc479704773159b905a3ad82d2bad7762d81a366cc46fbb2e2327f5c";

        // when
        String fingerprint = HashUtils.generateFingerprint(input);

        // then
        Assertions.assertEquals(exp, fingerprint);
    }

    @Test
    void generateFingerprint_WithString_Success() {
        // given
        byte[] input = new byte[] { 1, 2, 3, 4 };
        String exp = "5a667d62430a8c253ebae433333904dc6e1d41dcdc479704773159b905a3ad82d2bad7762d81a366cc46fbb2e2327f5c";

        // when
        String fingerprint = HashUtils.generateFingerprint(new String(input));

        // then
        Assertions.assertEquals(exp, fingerprint);
    }

    @Test
    void generateFingerprintSha256_Success() {
        // given
        byte[] input = new byte[] { 1, 2, 3, 4 };
        String exp = "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a";

        // when
        String fingerprint = HashUtils.generateSha256Fingerprint(input);

        // then
        Assertions.assertEquals(exp, fingerprint);
    }

    @Test
    void getIntForSha384_Success() {
        // given
        byte[] input = "".getBytes();

        // when
        int msb32 = HashUtils.getIntForSha384(input);

        // then
        Assertions.assertEquals(1538889800, msb32);
    }

    @Test
    void getIntForSha256_Success() {
        // given
        byte[] input = "".getBytes();

        // when
        int msb32 = HashUtils.getIntForSha256(input);

        // then
        Assertions.assertEquals(1438143096, msb32);
    }

    @Test
    void get20MSBytesForSha384_Success() {
        // given
        byte[] input = "test".getBytes();

        // when
        byte[] msb20 = HashUtils.getMSBytesForSha384(input, 20);

        // then
        Assertions.assertArrayEquals(fromHex("768412320F7B0AA5812FCE428DC4706B3CAE50E0"), msb20);
    }

    @Test
    void get12MSBytesForSha384_Success() {
        // given
        byte[] input = "test".getBytes();

        // when
        byte[] msb12 = HashUtils.getMSBytesForSha384(input, 12);

        // then
        Assertions.assertArrayEquals(fromHex("768412320F7B0AA5812FCE42"), msb12);
    }
}
