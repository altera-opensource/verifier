/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.model.dice;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TcbInfoKeyTest {

    private static final Map<TcbInfoField, Object> MAP = new HashMap<>();
    private static final String VENDOR = "VENDOR";
    private static final String MODEL = "MODEL";
    private static final Integer LAYER = 1;
    private static final Integer INDEX = 2;
    private static final String TYPE = "TYPE";

    @Mock
    private TcbInfo tcbInfo;

    @BeforeAll
    static void init() {
        MAP.put(TcbInfoField.VENDOR, VENDOR);
        MAP.put(TcbInfoField.MODEL, MODEL);
        MAP.put(TcbInfoField.LAYER, LAYER);
        MAP.put(TcbInfoField.INDEX, INDEX);
        MAP.put(TcbInfoField.TYPE, TYPE);
    }

    @Test
    void from_Empty() {
        // when
        final TcbInfoKey result = TcbInfoKey.from(new TcbInfo());

        // then
        Assertions.assertNull(result.getVendor());
        Assertions.assertNull(result.getModel());
        Assertions.assertNull(result.getLayer());
        Assertions.assertNull(result.getType());

        Assertions.assertEquals(0, result.getIndex());
    }

    @Test
    void from_AllSet() {
        // given
        when(tcbInfo.getTcbInfo()).thenReturn(MAP);

        // when
        final TcbInfoKey result = TcbInfoKey.from(tcbInfo);

        // then
        Assertions.assertEquals(VENDOR, result.getVendor());
        Assertions.assertEquals(MODEL, result.getModel());
        Assertions.assertEquals(LAYER, result.getLayer());
        Assertions.assertEquals(INDEX, result.getIndex());
        Assertions.assertEquals(TYPE, result.getType());
    }

    @Test
    void toString_Empty() {
        // given
        final String expected = "TcbInfoKey( index=0 )";

        // when
        final String result = TcbInfoKey.from(new TcbInfo()).toString();

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void toString_AllSet() {
        // given
        when(tcbInfo.getTcbInfo()).thenReturn(MAP);
        final String expected = "TcbInfoKey( vendor=VENDOR model=MODEL layer=1 index=2 type=TYPE )";

        // when
        final String result = TcbInfoKey.from(tcbInfo).toString();

        // then
        Assertions.assertEquals(expected, result);
    }
}
