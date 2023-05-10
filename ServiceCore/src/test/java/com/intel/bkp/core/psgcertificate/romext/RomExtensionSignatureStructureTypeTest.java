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

import com.intel.bkp.core.psgcertificate.PsgCancellableBlock0EntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.model.PsgRootCertMagic;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static com.intel.bkp.core.psgcertificate.romext.RomExtensionSignatureStructureType.BLOCK0;
import static com.intel.bkp.core.psgcertificate.romext.RomExtensionSignatureStructureType.LEAF;
import static com.intel.bkp.core.psgcertificate.romext.RomExtensionSignatureStructureType.ROOT;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class RomExtensionSignatureStructureTypeTest {

    @Test
    void findByMagic_PsgRootCertSingleMagic_ReturnsRoot() {
        findByMagic_ReturnsExpected(PsgRootCertMagic.SINGLE.getValue(), ROOT);
    }

    @Test
    void findByMagic_PsgRootCertMultiMagic_ReturnsRoot() {
        findByMagic_ReturnsExpected(PsgRootCertMagic.MULTI.getValue(), ROOT);
    }

    @Test
    void findByMagic_PsgCertificateEntryMagic_ReturnsLeaf() {
        findByMagic_ReturnsExpected(PsgCertificateEntryBuilder.PUBLIC_KEY_ENTRY_MAGIC, LEAF);
    }

    @Test
    void findByMagic_PsgCancellableBlock0EntryMagic_ReturnsBlock0() {
        findByMagic_ReturnsExpected(PsgCancellableBlock0EntryBuilder.MAGIC, BLOCK0);
    }

    @Test
    void findByMagic_UnknownMagic_ReturnsEmpty() {
        findByMagic_ReturnsExpected(1, Optional.empty());
    }

    private void findByMagic_ReturnsExpected(int magic, RomExtensionSignatureStructureType expectedType) {
        findByMagic_ReturnsExpected(magic, Optional.of(expectedType));
    }

    private void findByMagic_ReturnsExpected(int magic, Optional<RomExtensionSignatureStructureType> expected) {
        // when
        final var result = RomExtensionSignatureStructureType.findByMagic(magic);

        // then
        assertEquals(expected, result);
    }
}
