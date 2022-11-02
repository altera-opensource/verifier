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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TclCommandsTest {

    private final TclCommands sut = new TclCommands();

    @Test
    void initialize_CallsInternalCommandWithTransportId() {
        // given
        int transportId = 999;

        // when
        final String result = sut.initialize(transportId);

        // then
        assertTrue(result.contains("claim_packet_service_internal 999"));
        assertFalse(result.contains(TclCommands.CABLE_ID));
    }

    @Test
    void initialize_WithCableIdNull_CallsInternalCommandWithEmptyString() {
        // when
        final String result = sut.initialize(null);

        // then
        assertTrue(result.contains("claim_packet_service_internal \"\""));
        assertFalse(result.contains(TclCommands.CABLE_ID));
    }

    @Test
    void sendPacket_Success() {
        // given
        String command = "myCustomCommand";

        // when
        final String result = sut.sendPacket(command);

        // then
        assertTrue(result.contains(command));
        assertFalse(result.contains(TclCommands.COMMAND));
    }
}
