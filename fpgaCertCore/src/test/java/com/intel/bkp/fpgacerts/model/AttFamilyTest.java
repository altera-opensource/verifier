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

package com.intel.bkp.fpgacerts.model;

import com.intel.bkp.fpgacerts.exceptions.UnknownFamilyIdException;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Locale;

class AttFamilyTest {

    @Test
    void getFamilyName_Success() {
        // when
        final String actual = AttFamily.AGILEX.getFamilyName();

        // then
        Assertions.assertEquals("agilex", actual);
    }

    @Test
    void getFamilyId_Success() {
        // when
        final byte actual = AttFamily.AGILEX.getFamilyId();

        // then
        Assertions.assertEquals((byte) 52, actual);
    }

    @Test
    void from_byte_Success() {
        // given
        final AttFamily expected = AttFamily.AGILEX;
        final byte familyId = expected.getFamilyId();

        // when
        final AttFamily actual = AttFamily.from(familyId);

        // then
        Assertions.assertEquals(expected, actual);
    }

    @Test
    void from_byte_UnknownFamilyId_Throws() {
        // given
        final byte unknownFamilyId = 0x00;

        // when-then
        Assertions.assertThrows(UnknownFamilyIdException.class, () -> AttFamily.from(unknownFamilyId));
    }

    @Test
    void from_String_Lowercase_Success() {
        // given
        final AttFamily expected = AttFamily.AGILEX;
        final String familyNameInLowercase = expected.getFamilyName().toLowerCase(Locale.ROOT);

        // when
        final AttFamily actual = AttFamily.from(familyNameInLowercase);

        // then
        Assertions.assertEquals(expected, actual);
    }

    @Test
    void from_String_FirstLetterCapitalized_Success() {
        // given
        final AttFamily expected = AttFamily.AGILEX;
        final String familyNameCapitalized = StringUtils.capitalize(expected.getFamilyName());

        // when
        final AttFamily actual = AttFamily.from(familyNameCapitalized);

        // then
        Assertions.assertEquals(expected, actual);
    }

    @Test
    void from_String_Uppercase_Throws() {
        // given
        final String familyNameInUppercase = AttFamily.AGILEX.getFamilyName().toUpperCase(Locale.ROOT);

        // when-then
        Assertions.assertThrows(UnknownFamilyIdException.class, () -> AttFamily.from(familyNameInUppercase));
    }

    @Test
    void from_String_UnknownFamilyName_Throws() {
        // given
        final String unknownFamilyName = "blabla";

        // when-then
        Assertions.assertThrows(UnknownFamilyIdException.class, () -> AttFamily.from(unknownFamilyName));
    }
}
