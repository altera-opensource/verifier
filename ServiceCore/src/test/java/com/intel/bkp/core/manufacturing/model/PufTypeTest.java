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

package com.intel.bkp.core.manufacturing.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PufTypeTest {

    @Test
    void fromOrdinal_Success() {
        // given
        PufType expected = PufType.INTEL_USER;

        // when
        final PufType actual = PufType.fromOrdinal(expected.ordinal());

        // then
        assertEquals(expected, actual);
    }

    @Test
    void fromOrdinal_WithWrongEnumOrdinalMax_ThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> PufType.fromOrdinal(999));
    }

    @Test
    void fromOrdinal_WithWrongEnumOrdinalMin_ThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> PufType.fromOrdinal(-10));
    }

    @Test
    public void fromOrdinalInteger_Success() {
        // given
        Integer ordinal = 3;

        // when
        final PufType result = PufType.fromOrdinal(ordinal);

        // then
        assertEquals(PufType.IIDUSER, result);
    }

    @Test
    public void fromOrdinal_WithNull_ThrowsException() {
        // given
        Integer ordinal = null;

        // when-then
        assertThrows(NullPointerException.class, () -> PufType.fromOrdinal(ordinal));
    }

    @Test
    public void fromOrdinal_WithOrdinalOutOfRange_ThrowsException() {
        // given
        int ordinal = 150;

        // when-then
        assertThrows(IllegalArgumentException.class, () -> PufType.fromOrdinal(ordinal));
    }

    @Test
    public void getPufTypeHex_fromString() {
        // given
        String iid = "IID";

        // when-then
        assertEquals("00000000", PufType.getPufTypeHex(iid));
    }

    @Test
    public void getPufTypeHex_fromStringIntelUser() {
        // given
        String intelUser = "INTEL_USER";

        // when-then
        assertEquals("00000004", PufType.getPufTypeHex(intelUser));
    }

    @Test
    public void getPufTypeHex_fromPufTypeIntelUser() {
        // given
        PufType intelUser = PufType.INTEL_USER;

        // when-then
        assertEquals("00000004", PufType.getPufTypeHex(intelUser));
    }

    @Test
    public void getPufTypeHex_fromString_ThrowsException() {
        // given
        String nonexistent = "nonexistent";

        // when-then
        assertThrows(IllegalArgumentException.class, () -> PufType.getPufTypeHex(nonexistent));
    }
}
