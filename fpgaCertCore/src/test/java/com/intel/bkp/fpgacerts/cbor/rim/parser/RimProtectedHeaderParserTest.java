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

import com.intel.bkp.fpgacerts.cbor.ProtectedHeader;
import com.intel.bkp.utils.HexConverter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class RimProtectedHeaderParserTest {

    private static final String PROTECTED_HEX = "A401382203746170706C69636174696F6E2F72696D2B63626F720454A2E838F4AAC6" +
        "698CDAA4EB13C165E101675BBEF008A10082A2006F44657369676E5F456E67696E6565720201A20074436F6D6D6F6E4E616D654F7248" +
        "6F73746E616D650202";

    private static final byte[] PROTECTED = HexConverter.fromHex(PROTECTED_HEX);

    private final RimProtectedHeaderParser sut = RimProtectedHeaderParser.instance();

    @Test
    void parse_Success() {
        // when
        final ProtectedHeader entity = sut.parse(PROTECTED);

        // then
        assertNotNull(entity);
        assertEquals("A2E838F4AAC6698CDAA4EB13C165E101675BBEF0", entity.getIssuerKeyId());
    }
}
