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

package com.intel.bkp.fpgacerts.cbor.xrim.builder;

import com.intel.bkp.fpgacerts.cbor.rim.ProtectedSignersItem;
import com.intel.bkp.fpgacerts.cbor.utils.CborDateConverter;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimProtectedMetaMap;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

class XrimProtectedHeaderBuilderTest {

    private static final String XRIM_PROTECTED_META_MAP = "A200A1006F4669726D7761726520417574686F7201C074323032332D303"
        + "92D33305432333A35393A35395A";

    @Test
    void buildMetaMap_WithXrimData_Success() {
        // given
        final var header = prepareProtectedHeader();

        // when
        final byte[] actual = XrimProtectedHeaderBuilder.instance().buildMetaMap(header);

        // then
        assertEquals(XRIM_PROTECTED_META_MAP, toHex(actual));
    }

    private static XrimProtectedHeader prepareProtectedHeader() {
        return XrimProtectedHeader.builder()
            .metaMap(
                XrimProtectedMetaMap.builder()
                    .metaItem(
                        ProtectedSignersItem.builder()
                            .entityName("Firmware Author")
                            .build()
                    )
                    .issuedDate(CborDateConverter.fromString("2023-09-30T23:59:59Z"))
                    .build()
            ).build();
    }
}
