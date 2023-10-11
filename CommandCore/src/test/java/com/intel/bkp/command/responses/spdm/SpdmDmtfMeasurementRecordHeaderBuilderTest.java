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

package com.intel.bkp.command.responses.spdm;

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.utils.ByteBufferSafe;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SpdmDmtfMeasurementRecordHeaderBuilderTest {

    @Test
    void parse_build_DeviceStateHeader_Success() {
        // given
        final String expectedType = "82";
        final String expectedSize = "08";
        final String header = "820800";

        // when
        final SpdmDmtfMeasurementHeader result = buildHeader(header);

        // then
        assertEquals(expectedType, toHex(result.getType()));
        assertEquals(expectedSize, toHex(result.getSize()));
    }

    @Test
    void parse_build_UserDesignHeader_Success() {
        // given
        final String expectedType = "01";
        final String expectedSize = "30";
        final String header = "013000";

        // when
        final SpdmDmtfMeasurementHeader result = buildHeader(header);

        // then
        assertEquals(expectedType, toHex(result.getType()));
        assertEquals(expectedSize, toHex(result.getSize()));
    }

    private static SpdmDmtfMeasurementHeader buildHeader(String header) {
        return new SpdmDmtfMeasurementRecordHeaderBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(ByteBufferSafe.wrap(fromHex(header)))
            .withActor(EndiannessActor.SERVICE)
            .build();
    }
}
