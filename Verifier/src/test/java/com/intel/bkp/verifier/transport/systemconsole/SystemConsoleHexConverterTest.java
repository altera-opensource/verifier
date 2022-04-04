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

package com.intel.bkp.verifier.transport.systemconsole;

import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SystemConsoleHexConverterTest {

    @Test
    void toString_With0Bytes_ReturnsEmpty() {
        // when
        String result = SystemConsoleHexConverter.toString(new byte[0]);

        // then
        Assertions.assertEquals("", result);
    }

    @Test
    void toString_With4Bytes_ReturnsProperString() {
        // when
        String result = SystemConsoleHexConverter.toString(new byte[]{1, 2, 3, 4});

        // then
        Assertions.assertEquals("0x04030201", result);
    }

    @Test
    void toString_With8Bytes_ReturnsProperString() {
        // when
        String result = SystemConsoleHexConverter.toString(new byte[]{1, 2, 3, 4, 5, 6, 7, 8});

        // then
        Assertions.assertEquals("0x04030201 0x08070605", result);
    }

    @Test
    void toString_WithInvalidArrayLen_Throws() {
        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> SystemConsoleHexConverter.toString(new byte[]{1, 2}));
    }

    @Test
    void fromString_With0Bytes_ReturnsEmpty() {
        // given
        String response = "";

        // when
        byte[] result = SystemConsoleHexConverter.fromString(response);

        // then
        Assertions.assertArrayEquals(new byte[0], result);
    }

    @Test
    void fromString_With4Bytes_ReturnsArray() {
        // given
        String response = "0x04030201";

        // when
        byte[] result = SystemConsoleHexConverter.fromString(response);

        // then
        Assertions.assertArrayEquals(new byte[] { 1, 2, 3, 4 }, result);
    }

    @Test
    void fromString_With8Bytes_ReturnsArray() {
        // given
        String response = "0x04030201 0x08070605";

        // when
        byte[] result = SystemConsoleHexConverter.fromString(response);

        // then
        Assertions.assertArrayEquals(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, result);
    }

    @Test
    void fromString_WithInvalidStringLen_ThrowsException() {
        // given
        String response = "0x04030201 0x0807";

        // when-then
        Assertions.assertThrows(ByteBufferSafeException.class, () -> SystemConsoleHexConverter.fromString(response));
    }

    @Test
    void fromString_WithInvalidStringLen2_ThrowsException() {
        // given
        String response = "0x04030201 0x0807060504030201";

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> SystemConsoleHexConverter.fromString(response));
    }

    @Test
    void fromString_WithInvalidHexString_ThrowsException() {
        // given
        String response = "0xZZZZZZZZ";

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> SystemConsoleHexConverter.fromString(response));
    }

    @Test
    void fromString_WithInvalidHexString2_ThrowsException() {
        // given
        String response = "0xZZZ";

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> SystemConsoleHexConverter.fromString(response));
    }

}
