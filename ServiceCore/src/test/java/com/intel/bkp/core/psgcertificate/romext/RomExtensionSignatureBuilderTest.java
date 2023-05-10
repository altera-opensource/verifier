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

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.psgcertificate.PsgCancellableBlock0EntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.model.PsgRootCertMagic;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import lombok.SneakyThrows;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.core.TestUtil.loadBinaryFile;
import static com.intel.bkp.utils.HexConverter.toHex;

class RomExtensionSignatureBuilderTest {

    private static final String TEST_FILES_PATH = "/testfiles/romext";
    final private static byte[] WRONG_MAGIC = ByteSwap.getSwappedArray(0x99999999, ByteSwapOrder.CONVERT);

    final static byte[] ROM_EXT_STRUCTURE_WITH_SIG =
        loadBinaryFile(TEST_FILES_PATH + "/dm_signed_2021_03_16.romext");

    @Test
    void parse_Success() {
        // when
        RomExtensionStructureBuilder builder = prepareBuilder();

        // then
        Assertions.assertNotNull(builder.getRomExtSigBuilder());
    }

    @Test
    void parse_WithNotEmptyBuffer_ThrowsException() {
        // given
        RomExtensionStructureBuilder builder = prepareBuilder();
        final byte[] signature = ArrayUtils.addAll(builder.getSignature(), new byte[]{1, 2, 3, 4, 5, 6, 7, 8});

        // when-then
        Assertions.assertThrows(ParseStructureException.class,
            () -> RomExtensionSignatureBuilder.instance().withActor(EndiannessActor.FIRMWARE)
                .parse(signature));
    }

    @Test
    void parse_WithPsgRootCertParseException_ThrowsException() {
        // given
        RomExtensionStructureBuilder builder = prepareBuilder();
        final byte[] signature = builder.getSignature();
        replaceStructureMagicInSignature(signature, PsgRootCertMagic.MULTI.getValue());

        // when-then
        Assertions.assertThrows(ParseStructureException.class,
            () -> RomExtensionSignatureBuilder.instance()
                .withActor(EndiannessActor.FIRMWARE)
                .parse(signature));
    }

    @Test
    void parse_WithPsgCertParseException_ThrowsException() {
        // given
        RomExtensionStructureBuilder builder = prepareBuilder();
        final byte[] signature = builder.getSignature();
        replaceStructureMagicInSignature(signature, PsgCertificateEntryBuilder.PUBLIC_KEY_ENTRY_MAGIC);

        // when-then
        Assertions.assertThrows(ParseStructureException.class,
            () -> RomExtensionSignatureBuilder.instance()
                .withActor(EndiannessActor.FIRMWARE)
                .parse(signature));
    }

    @Test
    void parse_WithPsgBlock0EntryParseException_ThrowsException() {
        // given
        RomExtensionStructureBuilder builder = prepareBuilder();
        final byte[] signature = builder.getSignature();
        replaceStructureMagicInSignature(signature, PsgCancellableBlock0EntryBuilder.MAGIC);

        // when-then
        Assertions.assertThrows(ParseStructureException.class,
            () -> RomExtensionSignatureBuilder.instance()
                .withActor(EndiannessActor.FIRMWARE)
                .parse(signature));
    }

    @Test
    void parse_WithMissingOneOfStructures_ThrowsException() {
        // given
        RomExtensionStructureBuilder builder = prepareBuilder();
        final byte[] signature = removeStructureMagicInSignature(builder.getSignature(),
            PsgCancellableBlock0EntryBuilder.MAGIC);

        // when-then
        Assertions.assertThrows(ParseStructureException.class,
            () -> RomExtensionSignatureBuilder.instance()
                .withActor(EndiannessActor.FIRMWARE)
                .parse(signature));
    }

    @SneakyThrows
    private static RomExtensionStructureBuilder prepareBuilder() {
        return new RomExtensionStructureBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(ROM_EXT_STRUCTURE_WITH_SIG);
    }

    private static void replaceStructureMagicInSignature(byte[] signature, int magic) {
        final String swappedMagic = toHex(ByteSwap.getSwappedArray(magic, ByteSwapOrder.CONVERT));
        int magicPosition = toHex(signature).indexOf(swappedMagic);
        if (magicPosition > 0) {
            magicPosition = magicPosition / 2; // Hex contains 2 letters for 1 byte
        }
        System.arraycopy(WRONG_MAGIC, 0, signature, magicPosition, Integer.BYTES);
    }

    private static byte[] removeStructureMagicInSignature(byte[] signature, int magic) {
        final String swappedMagic = toHex(ByteSwap.getSwappedArray(magic, ByteSwapOrder.CONVERT));
        int magicPosition = toHex(signature).indexOf(swappedMagic);
        if (magicPosition > 0) {
            magicPosition = magicPosition / 2; // Hex contains 2 letters for 1 byte
        }
        byte[] subStructure = new byte[magicPosition];
        final ByteBufferSafe buffer = ByteBufferSafe.wrap(signature);
        buffer.get(subStructure);
        return subStructure;
    }
}
