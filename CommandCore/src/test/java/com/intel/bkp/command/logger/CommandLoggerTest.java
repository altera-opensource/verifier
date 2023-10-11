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

package com.intel.bkp.command.logger;

import com.intel.bkp.command.messages.BaseMessage;
import com.intel.bkp.command.responses.BaseResponse;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CommandLoggerTest {

    private static final byte[] MESSAGE = new byte[8];
    private static final String EXPECTED_MESSAGE_HEX = "0000000000000000";

    @Test
    void log_WithBaseMessage() {
        // given
        CommandLoggerValues dataName = CommandLoggerValues.CERTIFICATE_MESSAGE;

        // when
        String result = CommandLogger.log(new BaseMessage() {
            @Override
            public byte[] array() {
                return MESSAGE;
            }
        }, dataName, this.getClass());

        // then
        assertTrue(result.contains(EXPECTED_MESSAGE_HEX));
        assertTrue(result.contains(dataName.toString()));
        assertTrue(result.contains(this.getClass().getSimpleName()));
    }

    @Test
    void log_WithBaseResponse() {
        // given
        CommandLoggerValues dataName = CommandLoggerValues.CERTIFICATE_RESPONSE;

        // when
        String result = CommandLogger.log(new BaseResponse() {
            @Override
            public byte[] array() {
                return MESSAGE;
            }
        }, dataName, this.getClass());

        // then
        assertTrue(result.contains(EXPECTED_MESSAGE_HEX));
        assertTrue(result.contains(dataName.toString()));
        assertTrue(result.contains(this.getClass().getSimpleName()));
    }
}
