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

package com.intel.bkp.fpgacerts.url.params.parsing;

import com.intel.bkp.fpgacerts.dice.subject.DiceCertificateSubject;
import com.intel.bkp.fpgacerts.model.SmartNicFamily;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

import java.util.Locale;

import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class NicDiceParamsSubjectParserTest {

    private static final String SKI = "skiInBase64Url";
    private static final SmartNicFamily FAMILY = SmartNicFamily.CNV;
    private static final String FAMILY_NAME = StringUtils.capitalize(FAMILY.getFamilyName().toLowerCase(Locale.ROOT));
    private static final String DEVICE_ID = "01020304050607ab";

    private NicDiceParamsSubjectParser sut = new NicDiceParamsSubjectParser();

    @Test
    void getDiceParams_Success() {
        // when
        final var result = sut.getDiceParams(SKI, createDiceSubject(FAMILY_NAME));

        // then
        assertEquals(SKI, result.getId());
        assertEquals(DEVICE_ID, result.getUid());
        assertEquals(FAMILY, result.getFamily());
        assertEquals(toHex(FAMILY.getFamilyId()), result.getFamilyId());
    }

    @Test
    void getDiceParams_UnknownFamilyNameInSubject_Throws() {
        // when-then
        assertThrows(IllegalArgumentException.class,
            () -> sut.getDiceParams(SKI, createDiceSubject("unknown family name")));
    }

    private DiceCertificateSubject createDiceSubject(String familyName) {
        return new DiceCertificateSubject("company", familyName, "level", "data", DEVICE_ID);
    }
}
