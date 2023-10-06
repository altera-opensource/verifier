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

package com.intel.bkp.fpgacerts.dice.tcbinfo;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.EnumMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class TcbInfoMeasurementsAggregatorTest {

    private static final int MAX_FUZZ_STR_LEN = 1000;
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

    private static final TcbInfoMeasurement TCB_INFO_MEASUREMENT = new TcbInfoMeasurement(prepareTcbInfo());

    private TcbInfoMeasurementsAggregator sut;

    private static TcbInfo prepareTcbInfo() {
        final var map = Map.of(
            TcbInfoField.VENDOR, VENDOR,
            TcbInfoField.MODEL, MODEL,
            TcbInfoField.VERSION, VERSION,
            TcbInfoField.LAYER, LAYER,
            TcbInfoField.INDEX, INDEX,
            TcbInfoField.FWIDS, FWIDS,
            TcbInfoField.FLAGS, FLAGS,
            TcbInfoField.VENDOR_INFO, VENDOR_INFO,
            TcbInfoField.TYPE, TYPE
        );
        return new TcbInfo(map);
    }

    private static String getFuzzStr(FuzzedDataProvider data) {
        return data.consumeAsciiString(MAX_FUZZ_STR_LEN);
    }

    @BeforeEach
    void setUp() {
        sut = new TcbInfoMeasurementsAggregator();
    }

    @Tag("Fuzz")
    @FuzzTest
    void add_NewEachTime_ShouldBeAddedProperly_Fuzz(FuzzedDataProvider data) {
        // given
        final var sut = new TcbInfoMeasurementsAggregator();
        final var fwId = new FwIdField(getFuzzStr(data), getFuzzStr(data));
        final var vendorInfo = new MaskedVendorInfo(getFuzzStr(data));

        final var inputMap = Map.of(
            TcbInfoField.VENDOR, getFuzzStr(data),
            TcbInfoField.MODEL, getFuzzStr(data),
            TcbInfoField.VERSION, getFuzzStr(data),
            TcbInfoField.LAYER, data.consumeInt(),
            TcbInfoField.INDEX, data.consumeInt(),
            TcbInfoField.FWIDS, fwId,
            TcbInfoField.FLAGS, getFuzzStr(data),
            TcbInfoField.VENDOR_INFO, vendorInfo,
            TcbInfoField.TYPE, getFuzzStr(data)
        );
        final var tcbInfoMeasurement = new TcbInfoMeasurement(new TcbInfo(inputMap));

        // when
        sut.add(tcbInfoMeasurement);

        // then
        final Map<TcbInfoKey, TcbInfoValue> map = sut.getMap();
        assertEquals(1, map.size());
        assertTrue(map.containsKey(tcbInfoMeasurement.getKey()));
        assertEquals(map.get(tcbInfoMeasurement.getKey()), tcbInfoMeasurement.getValue());
    }

    @Tag("Fuzz")
    @FuzzTest
    void add_SameKeyDifferentValue_ShouldThrowException_Fuzz(FuzzedDataProvider data) {
        // given
        sut.add(TCB_INFO_MEASUREMENT);

        final var fwId = new FwIdField(getFuzzStr(data), getFuzzStr(data));
        final var vendorInfo = new MaskedVendorInfo(getFuzzStr(data));

        final var inputMap = Map.of(
            // key
            TcbInfoField.VENDOR, VENDOR,
            TcbInfoField.MODEL, MODEL,
            TcbInfoField.LAYER, LAYER,
            TcbInfoField.INDEX, INDEX,
            TcbInfoField.TYPE, TYPE,
            // value
            TcbInfoField.FWIDS, fwId,
            TcbInfoField.VERSION, getFuzzStr(data),
            TcbInfoField.FLAGS, getFuzzStr(data),
            TcbInfoField.VENDOR_INFO, vendorInfo
        );
        final var tcbInfoMeasurement = new TcbInfoMeasurement(new TcbInfo(inputMap));

        // when
        assertThrows(IllegalArgumentException.class, () -> sut.add(tcbInfoMeasurement));
    }

    @Test
    void add_IsAddedProperly() {
        // when
        sut.add(TCB_INFO_MEASUREMENT);

        // then
        final Map<TcbInfoKey, TcbInfoValue> map = sut.getMap();
        assertEquals(1, map.size());
        assertTrue(map.containsKey(TCB_INFO_MEASUREMENT.getKey()));
        assertEquals(map.get(TCB_INFO_MEASUREMENT.getKey()), TCB_INFO_MEASUREMENT.getValue());
    }

    @Test
    void mapToString_Success() {
        // given
        final var expected = "\n{\n\tTcbInfoKey( vendor=VENDOR model=MODEL layer=1 index=2 type=TYPE )  =  "
            + "TcbInfoValue( version=VERSION fwid=FwIdField( hashAlg=HASH_ALG digest=DIGEST ) "
            + "maskedVendorInfo=MaskedVendorInfo( vendorInfo=VENDOR_INFO ) flags=FLAGS )\n}\n";
        sut.add(TCB_INFO_MEASUREMENT);

        // when
        final String actual = sut.mapToString();

        // then
        assertEquals(expected, actual);
    }

    @Test
    void add_ElementAlreadyExists_IsNotAdded() {
        // given
        sut.add(TCB_INFO_MEASUREMENT);

        // when
        sut.add(TCB_INFO_MEASUREMENT);

        // then
        final Map<TcbInfoKey, TcbInfoValue> map = sut.getMap();
        assertEquals(1, map.size());
    }

    @Test
    void add_ElementAlreadyExistsAndValueIsSameWithVendorInfo_DoesNotThrow() {
        // given
        final var map = new EnumMap<>(TcbInfoField.class);
        map.put(TcbInfoField.VENDOR, VENDOR); // key
        map.put(TcbInfoField.VENDOR_INFO, VENDOR_INFO); // value
        final var tcbInfo = new TcbInfo(map);
        final var measurement = new TcbInfoMeasurement(tcbInfo);
        map.replace(TcbInfoField.VENDOR_INFO, new MaskedVendorInfo(VENDOR_INFO_STR));
        final var modifiedMeasurement = new TcbInfoMeasurement(tcbInfo);

        // when-then
        sut.add(measurement);
        assertDoesNotThrow(() -> sut.add(modifiedMeasurement));
        final Map<TcbInfoKey, TcbInfoValue> resultMap = sut.getMap();
        assertEquals(1, resultMap.size());
    }

    @Test
    void add_ElementAlreadyExistsButValueIsDifferentWithVendorInfo_Throws() {
        // given
        final var map = new EnumMap<>(TcbInfoField.class);
        map.put(TcbInfoField.VENDOR, VENDOR); // key
        map.put(TcbInfoField.VENDOR_INFO, VENDOR_INFO); // value
        final var tcbInfo = new TcbInfo(map);
        final var measurement = new TcbInfoMeasurement(tcbInfo);
        map.replace(TcbInfoField.VENDOR_INFO, new MaskedVendorInfo(VENDOR_INFO_DIFFERENT_STR));
        final var modifiedMeasurement = new TcbInfoMeasurement(tcbInfo);

        // when-then
        sut.add(measurement);
        assertThrows(IllegalArgumentException.class, () -> sut.add(modifiedMeasurement));
    }

    @Test
    void add_ElementAlreadyExistsAndValueIsSameWithFwIds_DoesNotThrow() {
        // given
        final var map = new EnumMap<>(TcbInfoField.class);
        map.put(TcbInfoField.VENDOR, VENDOR); // key
        map.put(TcbInfoField.FWIDS, FWIDS); // value
        final var tcbInfo = new TcbInfo(map);
        final var measurement = new TcbInfoMeasurement(tcbInfo);
        map.replace(TcbInfoField.FWIDS, new FwIdField(HASH_ALG, DIGEST));
        final var modifiedMeasurement = new TcbInfoMeasurement(tcbInfo);

        // when-then
        sut.add(measurement);
        assertDoesNotThrow(() -> sut.add(modifiedMeasurement));
        final Map<TcbInfoKey, TcbInfoValue> resultMap = sut.getMap();
        assertEquals(1, resultMap.size());
    }

    @Test
    void add_ElementAlreadyExistsButValueIsDifferentWithFwIds_Throws() {
        // given
        final var map = new EnumMap<>(TcbInfoField.class);
        map.put(TcbInfoField.VENDOR, VENDOR); // key
        map.put(TcbInfoField.FWIDS, FWIDS); // value
        final var tcbInfo = new TcbInfo(map);
        final var measurement = new TcbInfoMeasurement(tcbInfo);
        final FwIdField fwidsDifferent = new FwIdField();
        fwidsDifferent.setDigest("ABCD");
        map.replace(TcbInfoField.FWIDS, fwidsDifferent);
        final var modifiedMeasurement = new TcbInfoMeasurement(tcbInfo);

        // when-then
        sut.add(measurement);
        assertThrows(IllegalArgumentException.class, () -> sut.add(modifiedMeasurement));
    }
}
