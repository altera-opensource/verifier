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

package com.intel.bkp.fpgacerts.cbor.utils;

import com.intel.bkp.fpgacerts.cbor.exception.RimVerificationException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ProfileValidatorTest {

    @Test
    void verify_WithCorrectProfile_Success() {
        // when-then
        assertDoesNotThrow(() -> ProfileValidator.verify(List.of(ProfileValidator.EXPECTED_PROFILE)));
    }

    @Test
    void verify_WithIncorrectProfile_ThrowsException() {
        // given
        String profile = "4D3448693CA6F87BE997";

        // when-then
        final var ex = assertThrows(RimVerificationException.class,
            () -> ProfileValidator.verify(List.of(profile)));

        // then
        final String expected = """
            CoRIM verification failed:\s
            Detected unsupported profile: 1.37.52.72.105.60.638075 (4D3448693CA6F87BE997).
            Supported profile: 2.16.840.1.113741.1.15.6 (6086480186F84D010F06)""";
        assertEquals(expected, ex.getMessage());
    }

    @Test
    void verify_WithEmptyProfile_ThrowsException() {
        // when-then
        final var ex = assertThrows(RimVerificationException.class,
            () -> ProfileValidator.verify(List.of()));

        // then
        final String expected = """
            CoRIM verification failed:\s
            Detected unsupported profile: NONE.
            Supported profile: 2.16.840.1.113741.1.15.6 (6086480186F84D010F06)""";
        assertEquals(expected, ex.getMessage());
    }
}
