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

package com.intel.bkp.fpgacerts.cbor.xrim.parser;

import com.intel.bkp.fpgacerts.cbor.xrim.XrimUnsigned;
import com.intel.bkp.test.FileUtils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static org.junit.jupiter.api.Assertions.assertEquals;

class XrimUnsignedParserTest {

    private static final String ENTITY_NAME = "Firmware Author";
    private static final String REG_ID = "";
    private static final String DENY_LIST_ITEM = "51ac25b8dc58405cb4c94772120ba68a";
    private static final List<Integer> ROLES = List.of(1);

    private final XrimUnsignedParser sut = XrimUnsignedParser.instance();

    @Test
    void parse_Success() throws Exception {
        // given
        final byte[] cborData = FileUtils.readFromResources(TEST_FOLDER, "fw_xrim_unsigned.xrim");

        // when
        final XrimUnsigned entity = sut.parse(cborData);

        // then
        assertEquals(ENTITY_NAME, entity.getEntityMaps().get(0).getEntityName());
        assertEquals(REG_ID, entity.getEntityMaps().get(0).getRegId());
        assertEquals(ROLES, entity.getEntityMaps().get(0).getRoles());
        assertEquals(List.of(DENY_LIST_ITEM), entity.getDenyList());
    }
}
