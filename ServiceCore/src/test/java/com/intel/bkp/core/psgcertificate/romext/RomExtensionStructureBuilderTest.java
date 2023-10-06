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

import com.intel.bkp.core.RomExtensionAuthGeneratorUtil;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.RandomUtils;
import com.intel.bkp.test.enumeration.ResourceDir;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class RomExtensionStructureBuilderTest {

    final static byte[] DM_ROM_EXT_STRUCTURE_WITHOUT_SIG
        = FileUtils.loadBinary(ResourceDir.ROMEXT, "dm_signed_2021_03_16_without_sig.romext");
    final static byte[] DM_ROM_EXT_STRUCTURE_WITH_SIG =
        FileUtils.loadBinary(ResourceDir.ROMEXT, "dm_signed_2021_03_16.romext");
    // Values based on ManifestParser.exe result for file "dm_signed_2021_03_16_without_sig.romext"
    private static final int DM_EDI_ID = 0;
    private static final byte DM_FAMILY_ID = 0x35;
    private static final String DM_BUILD_IDENTIFIER_STRING = "Sign-RomExt-4";
    private static final String DM_ROM_EXT_HASH =
        "FB88D16205F231AEBCF3639FF63C42B45C6ED5DDD842F314572688E3DC2AE51A22FCE4913AE489969C0B6087DB3BB83C";

    final static byte[] FM_F7_ROM_EXT_WITH_SIG = FileUtils.loadBinary(ResourceDir.ROMEXT, "f7romext.romext");
    final static byte[] FM_F7_ROM_EXT_WITHOUT_SIG =
        FileUtils.loadBinary(ResourceDir.ROMEXT, "f7romext_without_sig.romext");

    // Values based on ManifestParser.exe result for file "f7romext_without_sig.romext"
    private static final int FM_EDI_ID = 0;
    private static final byte FM_FAMILY_ID = 0x34;
    private static final String FM_BUILD_IDENTIFIER_STRING = "Sign-RomExt-7";
    private static final String FM_ROM_EXT_HASH =
        "302E69BA6E3FAC340A57561234E88BFEB2FE373BCE4D4A28C244809CB467C31CA39874CD0D3F346FCA2A9AE874A1D66B";

    @Test
    void parse_WithDMStructure_Success() {
        // given
        var builder = new RomExtensionStructureBuilder()
            .withActor(EndiannessActor.FIRMWARE);

        // when
        builder.parse(DM_ROM_EXT_STRUCTURE_WITHOUT_SIG);

        // then
        assertEquals(DM_EDI_ID, builder.getEdiId());
        assertEquals(DM_FAMILY_ID, builder.getFamilyId());
        assertEquals(DM_BUILD_IDENTIFIER_STRING, builder.getBuildIdentifierString());
        assertEquals(DM_ROM_EXT_HASH, builder.calculateRomExtensionHash());
    }

    @Test
    void parse_WithFMStructure_Success() {
        // given
        var builder = new RomExtensionStructureBuilder()
            .withActor(EndiannessActor.FIRMWARE);

        // when
        builder.parse(FM_F7_ROM_EXT_WITHOUT_SIG);

        // then
        assertEquals(FM_EDI_ID, builder.getEdiId());
        assertEquals(FM_FAMILY_ID, builder.getFamilyId());
        assertEquals(FM_BUILD_IDENTIFIER_STRING, builder.getBuildIdentifierString());
        assertEquals(FM_ROM_EXT_HASH, builder.calculateRomExtensionHash());
    }

    @Test
    void build_WithDMStructureWithoutSig_BuildsSameHexData() {
        // given
        var builder = new RomExtensionStructureBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(DM_ROM_EXT_STRUCTURE_WITHOUT_SIG);

        // when
        final String actual = toHex(builder.build().array());

        // then
        assertEquals(toHex(DM_ROM_EXT_STRUCTURE_WITHOUT_SIG), actual);
    }

    @Test
    void build_WithFMStructureWithoutSig_BuildsSameHexData() {
        // given
        var builder = new RomExtensionStructureBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(FM_F7_ROM_EXT_WITHOUT_SIG);

        // when
        final String actual = toHex(builder.build().array());

        // then
        assertEquals(toHex(FM_F7_ROM_EXT_WITHOUT_SIG), actual);
    }

    @Test
    void build_WithDMStructure_WithSig_BuildsSameHexData() {
        // given
        var builder = new RomExtensionStructureBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(DM_ROM_EXT_STRUCTURE_WITH_SIG);

        // when
        final String actual = toHex(builder.build().array());

        // then
        assertEquals(toHex(DM_ROM_EXT_STRUCTURE_WITH_SIG), actual);
    }

    @Test
    void build_WithFMStructure_WithSig_BuildsSameHexData() {
        // given
        var builder = new RomExtensionStructureBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(FM_F7_ROM_EXT_WITH_SIG);

        // when
        final String actual = toHex(builder.build().array());

        // then
        assertEquals(toHex(FM_F7_ROM_EXT_WITH_SIG), actual);
    }

    @Test
    void parse_withWrongMagic_ThrowsException() {
        // given
        var builder = new RomExtensionStructureBuilder()
            .withActor(EndiannessActor.FIRMWARE);

        // when-then
        assertThrows(ParseStructureException.class, () -> builder.parse(new byte[]{1, 2, 3, 4, 5}));
    }

    @Test
    void parse_withLessBytesThanMagic_ThrowsException() {
        // given
        var builder = new RomExtensionStructureBuilder()
            .withActor(EndiannessActor.FIRMWARE);

        // when-then
        assertThrows(ParseStructureException.class, () -> builder.parse(new byte[]{1, 2, 3}));
    }

    @Test
    void build_WithCustomMockedData_BuildsAndParses() {
        // given
        final RomExtensionStructure initDataStructure = new RomExtensionStructureBuilder()
            .withFamily(FM_FAMILY_ID)
            .withUnusedFixedSize(new byte[]{2, 0, 8, 0})
            .withEdiId(0)
            .withUnusedVarySize(RandomUtils.generateRandomBytes(31264))
            .withBuildIdentifier(FM_BUILD_IDENTIFIER_STRING)
            .sign(dataToSign -> new RomExtensionAuthGeneratorUtil().signRomExtension(dataToSign))
            .withActor(EndiannessActor.FIRMWARE)
            .build();

        // when
        final RomExtensionStructureBuilder parsedData = new RomExtensionStructureBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(initDataStructure.array());

        // then
        assertEquals(FM_EDI_ID, parsedData.getEdiId());
        assertEquals(FM_FAMILY_ID, parsedData.getFamilyId());
        assertEquals(FM_BUILD_IDENTIFIER_STRING, parsedData.getBuildIdentifierString());
    }
}
