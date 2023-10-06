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

class AppArgumentParserTest {

    @Test
    void parseArguments_Success() {
        // given
        String[] args = new String[2];
        args[0] = "-i10";
        args[1] = "-cCREATE";

        final var expected = new AppArgument("10", CommandType.CREATE,
            null, null, null, null);

        // when
        final AppArgument result = AppArgumentParser.parseArguments(args);

        // then
        assertEquals(expected, result);
    }

    @Test
    void parseArgumentsAll_Success() {
        // given
        String pufType = "EFUSE";
        String[] args = new String[6];
        args[0] = "-i10";
        args[1] = "-cCREATE";
        args[2] = "--context=00010203";
        args[3] = "--puf-type=" + pufType;
        args[4] = "--ref-measurement=file";
        args[5] = "--log-level=INFO";

        final var expected = new AppArgument("10", CommandType.CREATE,
            "00010203", pufType, "file", "INFO");

        // when
        final AppArgument result = AppArgumentParser.parseArguments(args);

        // then
        assertEquals(expected, result);
    }
}
