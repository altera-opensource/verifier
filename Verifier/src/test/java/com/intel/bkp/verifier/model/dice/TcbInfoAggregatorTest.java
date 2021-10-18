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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TcbInfoAggregatorTest {

    private static final Map<TcbInfoField, Object> MAP = new HashMap<>();
    private static final String VENDOR = "VENDOR";
    private static final String MODEL = "MODEL";
    private static final String VERSION = "VERSION";
    private static final Integer LAYER = 1;
    private static final Integer INDEX = 2;
    private static final String HASH_ALG = "HASH_ALG";
    private static final String DIGEST = "DIGEST";
    private static final FwIdField FWIDS = new FwIdField(HASH_ALG, DIGEST);
    private static final String FLAGS = "FLAGS";
    private static final String VENDOR_INFO_STR = "VENDOR_INFO";
    private static final String VENDOR_INFO_DIFFERENT_STR = "VENDOR_INFO_DIFFERENT";
    private static final MaskedVendorInfo VENDOR_INFO = new MaskedVendorInfo(VENDOR_INFO_STR);
    private static final String TYPE = "TYPE";

    @Mock
    private TcbInfo tcbInfo;

    private TcbInfoAggregator sut;

    @BeforeAll
    static void init() {
        MAP.put(TcbInfoField.VENDOR, VENDOR);
        MAP.put(TcbInfoField.MODEL, MODEL);
        MAP.put(TcbInfoField.VERSION, VERSION);
        MAP.put(TcbInfoField.LAYER, LAYER);
        MAP.put(TcbInfoField.INDEX, INDEX);
        MAP.put(TcbInfoField.FWIDS, FWIDS);
        MAP.put(TcbInfoField.FLAGS, FLAGS);
        MAP.put(TcbInfoField.VENDOR_INFO, VENDOR_INFO);
        MAP.put(TcbInfoField.TYPE, TYPE);
    }

    @BeforeEach
    void setUp() {
        sut = new TcbInfoAggregator();
    }

    @Test
    void add_IsAddedProperly() {
        // given
        when(tcbInfo.getTcbInfo()).thenReturn(MAP);
        final TcbInfoKey expectedKey = TcbInfoKey.from(tcbInfo);
        final TcbInfoValue expectedValue = TcbInfoValue.from(tcbInfo);

        // when
        sut.add(tcbInfo);

        // then
        final Map<TcbInfoKey, TcbInfoValue> map = sut.getMap();
        Assertions.assertEquals(1, map.size());
        Assertions.assertTrue(map.containsKey(expectedKey));
        assertEquals(map.get(expectedKey), expectedValue);
    }

    @Test
    void add_ElementAlreadyExists_IsNotAdded() {
        // given
        when(tcbInfo.getTcbInfo()).thenReturn(MAP);
        sut.add(tcbInfo);

        // when
        sut.add(tcbInfo);

        // then
        final Map<TcbInfoKey, TcbInfoValue> map = sut.getMap();
        Assertions.assertEquals(1, map.size());
    }

    @Test
    void add_ElementAlreadyExistsAndValueIsSameWithVendorInfo_DoesNotThrow() {
        // given
        final Map<TcbInfoField, Object> map = new HashMap<>();
        map.put(TcbInfoField.VENDOR, VENDOR); // key
        map.put(TcbInfoField.VENDOR_INFO, VENDOR_INFO); // value
        when(tcbInfo.getTcbInfo()).thenReturn(map);
        sut.add(tcbInfo);

        map.replace(TcbInfoField.VENDOR_INFO, new MaskedVendorInfo(VENDOR_INFO_STR));

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.add(tcbInfo));
        final Map<TcbInfoKey, TcbInfoValue> resultMap = sut.getMap();
        Assertions.assertEquals(1, resultMap.size());
    }

    @Test
    void add_ElementAlreadyExistsButValueIsDifferentWithVendorInfo_Throws() {
        // given
        final Map<TcbInfoField, Object> map = new HashMap<>();
        map.put(TcbInfoField.VENDOR, VENDOR); // key
        map.put(TcbInfoField.VENDOR_INFO, VENDOR_INFO); // value
        when(tcbInfo.getTcbInfo()).thenReturn(map);
        sut.add(tcbInfo);

        map.replace(TcbInfoField.VENDOR_INFO, new MaskedVendorInfo(VENDOR_INFO_DIFFERENT_STR));

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> sut.add(tcbInfo));
    }

    @Test
    void add_ElementAlreadyExistsAndValueIsSameWithFwIds_DoesNotThrow() {
        // given
        final Map<TcbInfoField, Object> map = new HashMap<>();
        map.put(TcbInfoField.VENDOR, VENDOR); // key
        map.put(TcbInfoField.FWIDS, FWIDS); // value
        when(tcbInfo.getTcbInfo()).thenReturn(map);
        sut.add(tcbInfo);

        map.replace(TcbInfoField.FWIDS, new FwIdField(HASH_ALG, DIGEST));

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.add(tcbInfo));
        final Map<TcbInfoKey, TcbInfoValue> resultMap = sut.getMap();
        Assertions.assertEquals(1, resultMap.size());
    }

    @Test
    void add_ElementAlreadyExistsButValueIsDifferentWithFwIds_Throws() {
        // given
        final Map<TcbInfoField, Object> map = new HashMap<>();
        map.put(TcbInfoField.VENDOR, VENDOR); // key
        map.put(TcbInfoField.FWIDS, FWIDS); // value
        when(tcbInfo.getTcbInfo()).thenReturn(map);
        sut.add(tcbInfo);

        final FwIdField fwidsDifferent = new FwIdField();
        fwidsDifferent.setDigest("ABCD");
        map.replace(TcbInfoField.FWIDS, fwidsDifferent);

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> sut.add(tcbInfo));
    }
}
