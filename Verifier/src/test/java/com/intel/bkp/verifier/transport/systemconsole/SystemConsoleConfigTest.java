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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SystemConsoleConfigTest {

    //converted from 1-indexing to 0-indexing
    final Integer expectedCableId = 998;

    @Test
    void systemConsoleConfig_correctTransportId_Success() {
        //given
        final String transportId = "host:127.0.0.1; port:80; cableID:999";

        //when
        SystemConsoleConfig config = new SystemConsoleConfig(transportId);

        //then
        Assertions.assertEquals(expectedCableId, config.getCableId());
        Assertions.assertEquals(80, config.getPort());
        Assertions.assertEquals("127.0.0.1", config.getHost());
    }

    @Test
    void systemConsoleConfig_correctTransportIdWithWhitespaces_Success() {
        //given
        final String transportId = " host: 127.0.0.1;\nport: 80; cableID: 999  ";

        //when
        SystemConsoleConfig config = new SystemConsoleConfig(transportId);

        //then
        Assertions.assertEquals(expectedCableId, config.getCableId());
        Assertions.assertEquals(80, config.getPort());
        Assertions.assertEquals("127.0.0.1", config.getHost());
    }

    @Test
    void systemConsoleConfig_incorrectTransportIdWithoutCableId_Fail() {
        //given
        final String transportId = " host: 127.0.0.1;\nport: 80";

        //when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> new SystemConsoleConfig(transportId));
    }

    @Test
    void systemConsoleConfig_incorrectTransportIdWithWrongCableIdValue_Fail() {
        //given
        final String transportId = "host:127.0.0.1; port:80; cableID:0";

        //when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> new SystemConsoleConfig(transportId));
    }
}
