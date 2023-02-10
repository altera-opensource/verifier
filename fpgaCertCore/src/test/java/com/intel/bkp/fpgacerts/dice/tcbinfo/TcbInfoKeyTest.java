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

package com.intel.bkp.fpgacerts.dice.tcbinfo;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

@ExtendWith(MockitoExtension.class)
class TcbInfoKeyTest {

    private static final String VENDOR = "VENDOR";
    private static final String MODEL = "MODEL";
    private static final Integer LAYER = 1;
    private static final Integer INDEX = 2;
    private static final String TYPE = "TYPE";

    private static TcbInfo TCB_INFO;

    @BeforeAll
    static void init() {
        final Map<TcbInfoField, Object> map = Map.of(
            TcbInfoField.VENDOR, VENDOR,
            TcbInfoField.MODEL, MODEL,
            TcbInfoField.LAYER, LAYER,
            TcbInfoField.INDEX, INDEX,
            TcbInfoField.TYPE, TYPE
        );
        TCB_INFO = new TcbInfo(map);
    }

    @Test
    void from_Empty() {
        // when
        final TcbInfoKey result = TcbInfoKey.from(new TcbInfo());

        // then
        Assertions.assertNull(result.getVendor());
        Assertions.assertNull(result.getModel());
        Assertions.assertNull(result.getLayer());
        Assertions.assertNull(result.getIndex());
        Assertions.assertNull(result.getType());
    }

    @Test
    void from_AllSet() {
        // when
        final TcbInfoKey result = TcbInfoKey.from(TCB_INFO);

        // then
        Assertions.assertEquals(VENDOR, result.getVendor());
        Assertions.assertEquals(MODEL, result.getModel());
        Assertions.assertEquals(LAYER, result.getLayer());
        Assertions.assertEquals(INDEX, result.getIndex());
        Assertions.assertEquals(TYPE, result.getType());
    }

    @Test
    void from_MeasurementTypeAndModel_FillsVendorAndIndexWithDefaultsButLeavesTypeAsNull() {
        // given
        final MeasurementType measurementType = MeasurementType.CMF;

        // when
        final TcbInfoKey result = TcbInfoKey.from(measurementType, MODEL);

        // then
        Assertions.assertEquals("intel.com", result.getVendor());
        Assertions.assertEquals(MODEL, result.getModel());
        Assertions.assertEquals(measurementType.getLayer(), result.getLayer());
        Assertions.assertEquals(0, result.getIndex());
        Assertions.assertNull(result.getType());
    }

    @Test
    void from_MeasurementType_FillsVendorWithDefaultsButLeavesModelAndIndexAsNull() {
        // given
        final MeasurementType measurementType = MeasurementType.CMF;

        // when
        final TcbInfoKey result = TcbInfoKey.from(measurementType);

        // then
        Assertions.assertEquals("intel.com", result.getVendor());
        Assertions.assertEquals(measurementType.getOid(), result.getType());
        Assertions.assertEquals(measurementType.getLayer(), result.getLayer());
        Assertions.assertNull(result.getModel());
        Assertions.assertNull(result.getIndex());
    }

    @Test
    void toString_Empty() {
        // given
        final String expected = "TcbInfoKey( )";

        // when
        final String result = TcbInfoKey.from(new TcbInfo()).toString();

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void toString_AllSet() {
        // given
        final String expected = "TcbInfoKey( vendor=VENDOR model=MODEL layer=1 index=2 type=TYPE )";

        // when
        final String result = TcbInfoKey.from(TCB_INFO).toString();

        // then
        Assertions.assertEquals(expected, result);
    }
}
