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

package com.intel.bkp.fpgacerts.dice.tcbinfo;

import com.intel.bkp.fpgacerts.exceptions.FwidHashAlgNotSupported;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.FwidHashAlg.FWIDS_HASH_ALG_SHA384;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FwidHashAlgTest {

    @Test
    void from_WithSupportedSize_ReturnsValidObject() throws FwidHashAlgNotSupported {
        // when
        final FwidHashAlg result = FwidHashAlg.from(FWIDS_HASH_ALG_SHA384.getSize());

        // then
        assertEquals(FWIDS_HASH_ALG_SHA384, result);
    }

    @Test
    void from_WithNotSupportedSize_Throws() {
        // when-then
        final FwidHashAlgNotSupported exception =
            assertThrows(FwidHashAlgNotSupported.class, () -> FwidHashAlg.from(1));

        // then
        assertEquals("FwId hash algorithm of size 1 is not supported.", exception.getMessage());
    }

    @Test
    void isSupported_WithSupported_ReturnsTrue() {
        // when
        final boolean result = FwidHashAlg.isSupported(FWIDS_HASH_ALG_SHA384.getOid());

        // then
        assertTrue(result);
    }

    @Test
    void isSupported_WithNotSupported_ReturnsFalse() {
        // when
        final boolean result = FwidHashAlg.isSupported("1.2.3.4");

        // then
        assertFalse(result);
    }

    @Test
    void getSupported() {
        // when
        final String result = FwidHashAlg.getSupported();

        // then
        assertEquals("2.16.840.1.101.3.4.2.2", result);
    }
}
