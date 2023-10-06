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

package com.intel.bkp.fpgacerts.cbor.rim.builder;

import com.intel.bkp.fpgacerts.cbor.rim.ProtectedMetaMap;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedSignersItem;
import com.intel.bkp.fpgacerts.cbor.rim.RimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.utils.CborDateConverter;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RimProtectedBuilderTest {

    private static final String RIM_PROTECTED_META_MAP = "A20082A1006F4669726D7761726520417574686F72A10077434E3D496E74"
        + "656C3A4167696C65783A4D616E5369676E01A101C074323032332D30392D33305432333A35393A35395A";


    @Test
    void buildMetaMap_WithRimData_Success() {
        // given
        final var header = prepareProtectedHeader();

        // when
        final byte[] actual = RimProtectedBuilder.instance().buildMetaMap(header);

        // then
        assertEquals(RIM_PROTECTED_META_MAP, toHex(actual));
    }

    private static RimProtectedHeader prepareProtectedHeader() {
        return RimProtectedHeader.builder()
            .metaMap(ProtectedMetaMap.builder()
                .metaItems(
                    List.of(ProtectedSignersItem.builder()
                            .entityName("Firmware Author")
                            .build(),
                        ProtectedSignersItem.builder()
                            .entityName("CN=Intel:Agilex:ManSign")
                            .build())
                )
                .signatureValidity(CborDateConverter.fromString("2023-09-30T23:59:59Z"))
                .build())
            .build();
    }
}
