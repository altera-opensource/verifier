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

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class FirstIntegerByteParserTest {

    @Test
    void from_WithExistingEnumValue_Success() {
        // given
        final TestEnum expected = TestEnum.B;
        final byte[] id = new byte[]{expected.getId(), 0, 0, 0};

        // when
        final TestEnum result = FirstIntegerByteParser.from(id, TestEnum.values(), TestEnum::getId);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void from_WithNotExistingEnumValue_Throws() {
        assertThrows(new byte[]{0x9, 0, 0, 0});
    }

    @Test
    void from_WithLongDataSize_ThrowsException() {
        assertThrows(new byte[]{TestEnum.B.getId(), 0, 0, 0, 0, 0, 0, 0});
    }

    @Test
    void from_WithNotSupportedBytes_ThrowsException() {
        assertThrows(new byte[]{TestEnum.B.getId(), 0, 0, 0x1});
    }

    private static void assertThrows(byte[] unknownId) {
        // when-then
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> FirstIntegerByteParser.from(unknownId, TestEnum.values(), TestEnum::getId));
    }

    @Getter
    @AllArgsConstructor
    enum TestEnum {
        A((byte) 0x01),
        B((byte) 0x02);

        final byte id;
    }
}
