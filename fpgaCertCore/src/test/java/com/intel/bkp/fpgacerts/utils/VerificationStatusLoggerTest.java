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

package com.intel.bkp.fpgacerts.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class VerificationStatusLoggerTest {

    private static final String TEST_MSG = "Test message";

    private static final String EXPECTED_SUCCESS = "Test message [Passed]";
    private static final String EXPECTED_FAILURE = "Test message [Failed]";
    private static final String EXPECTED_SKIPPED = "Test message [Skipped]";

    @Test
    void success_Success() {
        // when
        final var actualMessage = VerificationStatusLogger.success(TEST_MSG);

        // then
        assertEquals(EXPECTED_SUCCESS, actualMessage);
    }

    @Test
    void failure_Success() {
        // when
        final var actualMessage = VerificationStatusLogger.failure(TEST_MSG);

        // then
        assertEquals(EXPECTED_FAILURE, actualMessage);
    }

    @Test
    void skipped_Success() {
        // when
        final var actualMessage = VerificationStatusLogger.skipped(TEST_MSG);

        // then
        assertEquals(EXPECTED_SKIPPED, actualMessage);
    }
}
