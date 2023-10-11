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

package com.intel.bkp.fpgacerts.model;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SmartNicFamilyTest {

    @Test
    void getFamilyName_Success() {
        // when
        final String actual = SmartNicFamily.CNV.getFamilyName();

        // then
        assertEquals("Enet Controller E830", actual);
    }

    @Test
    void getFamilyId_Success() {
        // when
        final byte actual = SmartNicFamily.CNV.getFamilyId();

        // then
        assertEquals(0x03, actual);
    }

    @Test
    void from_bytes_With4Bytes_WithOnlyFirstByteSet_Success() {
        // given
        final SmartNicFamily expected = SmartNicFamily.LKV;
        final byte[] familyId = new byte[]{expected.getFamilyId(), 0, 0, 0};

        // when
        final SmartNicFamily actual = SmartNicFamily.from(familyId);

        // then
        assertEquals(expected, actual);
    }

    @Test
    void from_bytes_With1Byte_Throws() {
        // given
        final SmartNicFamily expected = SmartNicFamily.LKV;
        final byte[] familyId = new byte[]{expected.getFamilyId()};

        // when-then
        assertThrows(IllegalArgumentException.class, () -> SmartNicFamily.from(familyId));
    }

    @Test
    void from_bytes_With4Bytes_WithOnlyFirstByteSet_WithUnknownFamilyId_Throws() {
        // given
        final byte[] familyId = new byte[]{0x7E};

        // when-then
        assertThrows(IllegalArgumentException.class, () -> SmartNicFamily.from(familyId));
    }

    @Test
    void from_String_FirstLetterCapitalized_Success() {
        // given
        final SmartNicFamily expected = SmartNicFamily.LKV;
        final String familyNameCapitalized = StringUtils.capitalize(expected.getFamilyName().toLowerCase(Locale.ROOT));

        // when
        final SmartNicFamily actual = SmartNicFamily.from(familyNameCapitalized);

        // then
        assertEquals(expected, actual);
    }

    @Test
    void from_String_FirstLetterOfEachWordCapitalized_Success() {
        // given
        final SmartNicFamily expected = SmartNicFamily.LKV;
        final String familyNameWithEachWordCapitalized = expected.getFamilyName();

        // when
        final SmartNicFamily actual = SmartNicFamily.from(familyNameWithEachWordCapitalized);

        // then
        assertEquals(expected, actual);
    }

    @Test
    void from_String_Lowercase_Throws() {
        // given
        final SmartNicFamily expected = SmartNicFamily.LKV;
        final String familyNameInLowercase = expected.getFamilyName().toLowerCase(Locale.ROOT);

        // when-then
        assertThrows(IllegalArgumentException.class, () -> SmartNicFamily.from(familyNameInLowercase));
    }

    @Test
    void from_String_Uppercase_Throws() {
        // given
        final String familyNameInUppercase = SmartNicFamily.LKV.getFamilyName().toUpperCase(Locale.ROOT);

        // when-then
        assertThrows(IllegalArgumentException.class, () -> SmartNicFamily.from(familyNameInUppercase));
    }

    @Test
    void from_String_UnknownFamilyName_Throws() {
        // given
        final String unknownFamilyName = "blabla";

        // when-then
        assertThrows(IllegalArgumentException.class, () -> SmartNicFamily.from(unknownFamilyName));
    }
}
