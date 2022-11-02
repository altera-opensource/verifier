/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2022 Intel Corporation. All Rights Reserved.
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

import com.intel.bkp.core.psgcertificate.exceptions.RomExtensionSignatureException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.core.psgcertificate.PsgCancellableBlock0EntryBuilder.MAGIC;
import static com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder.PUBLIC_KEY_ENTRY_MAGIC;
import static com.intel.bkp.core.psgcertificate.model.PsgRootCertMagic.MULTI;

class RomExtractedStructureDataTest {

    private static final byte[] SAMPLE_DATA = {1, 2, 3, 4};

    @Test
    void constructor_WithBlock0EntryMagic_Success() throws Exception {
        // when
        final var actual = new RomExtractedStructureData(MAGIC, SAMPLE_DATA);

        // then
        assertions(RomExtractedStructureStrategy.BLOCK0, actual);
    }

    @Test
    void constructor_WithRootCertMagicMulti_Success() throws Exception {
        // when
        final var actual = new RomExtractedStructureData(MULTI.getValue(), SAMPLE_DATA);

        // then
        assertions(RomExtractedStructureStrategy.ROOT, actual);
    }

    @Test
    void constructor_WithCertEntryMagic_Success() throws Exception {
        // when
        final var actual = new RomExtractedStructureData(PUBLIC_KEY_ENTRY_MAGIC, SAMPLE_DATA);

        // then
        assertions(RomExtractedStructureStrategy.LEAF, actual);
    }

    @Test
    void constructor_WithInvalidMagic_ThrowsException() {
        // when-then
        Assertions.assertThrows(RomExtensionSignatureException.class,
            () -> new RomExtractedStructureData(123, SAMPLE_DATA));
    }

    private static void assertions(RomExtractedStructureStrategy strategy, RomExtractedStructureData data) {
        Assertions.assertEquals(strategy, data.getType());
        Assertions.assertArrayEquals(SAMPLE_DATA, data.getData());
    }
}
