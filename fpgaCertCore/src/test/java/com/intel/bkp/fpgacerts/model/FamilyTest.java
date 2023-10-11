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

import com.intel.bkp.fpgacerts.exceptions.UnknownFamilyIdException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.Optional;

import static java.util.Arrays.stream;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FamilyTest {

    @ParameterizedTest
    @EnumSource(value = Family.class)
    void from_byte_Success(Family family) {
        // when
        final Family result = Family.from(family.getFamilyId());

        // then
        assertEquals(family, result);
    }

    @ParameterizedTest
    @EnumSource(value = Family.class)
    void from_Integer_Success(Family family) {
        // when
        final Family result = Family.from(family.getAsInteger());

        // then
        assertEquals(family, result);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(ints = {-2, 0, 32})
    void from_Integer_UnknownValue_Throws(Integer value) {
        // when-then
        assertThrows(UnknownFamilyIdException.class, () -> Family.from(value));
    }

    @ParameterizedTest
    @EnumSource(value = Family.class)
    void find_Success(Family family) {
        // when
        final Optional<Family> result = Family.find(family.getAsInteger());

        // then
        assertTrue(result.isPresent());
        assertEquals(family, result.get());
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(ints = {-2, 0, 32})
    void find_UnknownValue_ReturnsEmpty(Integer value) {
        // when
        final Optional<Family> result = Family.find(value);

        // then
        assertTrue(result.isEmpty());
    }

    @Test
    void getAllIds_Fpga_Success() {
        // given
        final var expected = new ArrayList<Integer>();
        expected.add(Family.S10.getAsInteger());
        expected.addAll(stream(AttFamily.values()).map(f -> f.getFamily().getAsInteger()).toList());

        // when
        final var result = Family.getAllIds(FamilyType.FPGA);

        // then
        assertIterableEquals(expected, result);
    }

    @Test
    void getAllIds_Nic_Success() {
        // given
        final var expected = stream(SmartNicFamily.values()).map(f -> f.getFamily().getAsInteger()).toList();

        // when
        final var result = Family.getAllIds(FamilyType.NIC);

        // then
        assertIterableEquals(expected, result);
    }

}
