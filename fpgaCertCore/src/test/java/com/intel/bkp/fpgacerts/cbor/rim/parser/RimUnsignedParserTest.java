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

package com.intel.bkp.fpgacerts.cbor.rim.parser;

import com.intel.bkp.fpgacerts.cbor.LocatorItem;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.intel.bkp.test.FileUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RimUnsignedParserTest {

    private static final String MANIFEST_ID = "51AC25B8DC58405CB4C94772120BA68A";

    private static final String LINK_CER =
        "https://tsci.intel.com/content/IPCS/certs/RIM_Signing_agilex_5WL28Ty-Nta3Si1dR3ralQ7jFHw.cer";
    private static final String LINK_XRIM =
        "https://tsci.intel.com/content/IPCS/crls/RIM_Signing_agilex_5WL28Ty-Nta3Si1dR3ralQ7jFHw.xrim";
    private static final String PROFILE = "6086480186F84D010F06";

    private byte[] cborData;

    private final RimUnsignedParser sut = RimUnsignedParser.instance();

    @BeforeEach
    void setUp() throws Exception {
        cborData = FileUtils.readFromResources(TEST_FOLDER, "fw_rim_unsigned.rim");
    }

    @Test
    void parse_Success() {
        // when
        final RimUnsigned entity = sut.parse(cborData);

        // then
        assertEquals(MANIFEST_ID, entity.getManifestId());
        assertTrue(entity.getLocators().contains(new LocatorItem(LocatorType.CER, LINK_CER)));
        assertTrue(entity.getLocators().contains(new LocatorItem(LocatorType.XCORIM, LINK_XRIM)));
        assertEquals(PROFILE, entity.getProfile().get(0));
    }
}
