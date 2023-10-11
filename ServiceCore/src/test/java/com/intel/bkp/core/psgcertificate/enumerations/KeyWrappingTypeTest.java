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

package com.intel.bkp.core.psgcertificate.enumerations;

import org.junit.jupiter.api.Test;

import java.util.List;

import static com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType.IID_PUF;
import static com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType.INTEL_PUF;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyWrappingTypeTest {

    @Test
    void fromValue_Success() {
        // when
        final KeyWrappingType result = KeyWrappingType.fromValue((byte) 0x01);

        // then
        assertEquals(KeyWrappingType.INTERNAL, result);
    }

    @Test
    void fromValue_InvalidValue_Throws() {
        // when-then
        assertThrows(IllegalArgumentException.class, () -> KeyWrappingType.fromValue((byte) 0x15));
    }

    @Test
    void testToString_SingleValue() {
        // when
        final String result = KeyWrappingType.IID_PUF.toString();

        // then
        assertEquals("IID_PUF (0x02)", result);
    }

    @Test
    void testToString_List() {
        // when
        final String result = List.of(IID_PUF, INTEL_PUF).toString();

        // then
        assertEquals("[IID_PUF (0x02), INTEL_PUF (0x03)]", result);
    }
}
