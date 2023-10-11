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

package com.intel.bkp.core.psgcertificate.romext;

import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.psgcertificate.PsgCancellableBlock0EntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.model.PsgRootCertMagic;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.core.psgcertificate.romext.RomExtensionSignatureStructureType.BLOCK0;
import static com.intel.bkp.core.psgcertificate.romext.RomExtensionSignatureStructureType.LEAF;
import static com.intel.bkp.core.psgcertificate.romext.RomExtensionSignatureStructureType.ROOT;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RomExtractedStructureDataTest {

    private static final byte[] SAMPLE_DATA = {1, 2, 3, 4};

    @Test
    void from_WithBlock0EntryMagic_Success() {
        from_ReturnsExpected(PsgCancellableBlock0EntryBuilder.MAGIC, BLOCK0);
    }

    @Test
    void from_WithRootCertMagicMulti_Success() {
        from_ReturnsExpected(PsgRootCertMagic.MULTI.getValue(), ROOT);
    }

    @Test
    void from_WithCertEntryMagic_Success() {
        from_ReturnsExpected(PsgCertificateEntryBuilder.PUBLIC_KEY_ENTRY_MAGIC, LEAF);
    }

    @Test
    void from_WithInvalidMagic_ThrowsException() {
        // when-then
        assertThrows(ParseStructureException.class,
            () -> RomExtractedStructureData.from(123, SAMPLE_DATA));
    }

    private static void from_ReturnsExpected(int magic, RomExtensionSignatureStructureType expectedType) {
        // when
        final var result = RomExtractedStructureData.from(magic, SAMPLE_DATA);

        // then
        assertEquals(expectedType, result.type());
        assertArrayEquals(SAMPLE_DATA, result.data());
    }
}
