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

package com.intel.bkp.core.psgcertificate.model;

import com.intel.bkp.core.exceptions.ParseStructureException;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PsgSignatureMagicTest {

    private static final String ALLOWED_MAGICS = "0x%s, 0x%s".formatted(
        toHex(PsgSignatureMagic.STANDARD.getValue()),
        toHex(PsgSignatureMagic.CANCELLABLE_BLOCK0_ENTRY.getValue())
    );
    ;

    @Test
    void getAllowedMagics_ReturnsListOfMagics() {
        // when
        final String actualList = PsgSignatureMagic.getAllowedMagics();

        // then
        assertEquals(ALLOWED_MAGICS, actualList);
    }

    @Test
    void from_Success() {
        // when-then
        assertDoesNotThrow(() -> PsgSignatureMagic.from(PsgSignatureMagic.STANDARD.getValue()));
    }

    @Test
    void from_WithInvalidMagic_Throws() {
        assertThrows(ParseStructureException.class, () -> PsgSignatureMagic.from(0));
    }
}
