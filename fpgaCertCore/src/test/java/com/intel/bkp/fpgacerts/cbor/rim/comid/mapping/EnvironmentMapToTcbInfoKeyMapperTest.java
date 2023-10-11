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

package com.intel.bkp.fpgacerts.cbor.rim.comid.mapping;

import com.intel.bkp.fpgacerts.cbor.rim.comid.EnvironmentMap;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnvironmentMapToTcbInfoKeyMapperTest {

    private final EnvironmentMapToTcbInfoKeyMapper sut = new EnvironmentMapToTcbInfoKeyMapper();

    @Test
    void map_fromEmptyEnvironmentMap_Success() {
        // given
        final var environmentMap = new EnvironmentMap(null, null, null, null, null);

        // when
        final var result = sut.map(environmentMap);

        // then
        assertTrue(result.isEmpty());
    }

    @Test
    void map_fromFilledEnvironmentMap_Success() {
        // given
        final String oidInHex = "6086480186F84D010F0403";
        final String oid = "2.16.840.1.113741.1.15.4.3";
        final String vendor = "intel.com";
        final String model = "Agilex";
        final Integer layer = 1;
        final Integer index = 0;
        final var environmentMap = new EnvironmentMap(oidInHex, vendor, model, layer, index);

        // when
        final var result = sut.map(environmentMap);

        // then
        assertEquals(oid, result.getType());
        assertEquals(vendor, result.getVendor());
        assertEquals(model, result.getModel());
        assertEquals(layer, result.getLayer());
        assertEquals(index, result.getIndex());
    }
}
