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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class UdsChoiceTest {

    @ParameterizedTest
    @EnumSource(UdsChoice.class)
    void from_withValidByte_Success(UdsChoice udsChoice) {
        // when
        final var result = UdsChoice.from(udsChoice.getFlag());

        // then
        assertEquals(udsChoice, result);
    }

    @ParameterizedTest
    @ValueSource(bytes = {0x0f, 0x11})
    void from_withInvalidByte_Throws(byte b) {
        // when-then
        assertThrows(IllegalArgumentException.class, () -> UdsChoice.from(b));
    }

    @Test
    void subfolders_ReturnsAllDpSubFoldersAsUnmodifiableList() {
        // given
        final var expected = List.of(
            UdsChoice.EFUSE.getDpSubDirectory(),
            UdsChoice.PUF.getDpSubDirectory()
        );

        // when
        final var result = UdsChoice.SUBFOLDERS;

        // then
        assertIterableEquals(expected, result);
        assertThrows(UnsupportedOperationException.class, () -> result.remove(0));
        assertThrows(UnsupportedOperationException.class, () -> result.add("someFolder"));
    }
}
