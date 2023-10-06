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

package com.intel.bkp.workload.util;

import com.intel.bkp.workload.model.CommandType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class AppArgumentBuilderTest {

    final String transportId = "host:127.0.0.1; port:80; cableID:999";

    @Test
    public void builder_Success() {
        // given
        CommandType command = CommandType.CREATE;
        String pufType = "EFUSE";

        // when
        final AppArgument result = AppArgument.instance()
            .transportId(transportId)
            .command(command.name())
            .context("999")
            .pufType(pufType)
            .refMeasurement("myTestMeasure")
            .logLevel("DEBUG")
            .build();

        // then
        assertNotNull(result);

        // Transport id is counted from 0 not 1
        assertEquals(transportId, result.getTransportId());
        assertEquals(command, result.getCommand());
        assertEquals(pufType, result.getPufType());
    }

    @Test
    public void builder_WithInvalidCommand_ReturnsEmptyCommand() {
        // given
        String command = "testCommandNotKnown";

        // when
        final AppArgument result = AppArgument.instance()
            .command(command)
            .build();

        // then
        assertNotNull(result);
        assertNull(result.getCommand());
    }

}
