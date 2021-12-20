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

package com.intel.bkp.verifier.command.responses.attestation;

import com.intel.bkp.ext.utils.ByteBufferSafe;
import com.intel.bkp.verifier.model.dice.TcbInfo;
import com.intel.bkp.verifier.model.dice.TcbInfoConstants;
import com.intel.bkp.verifier.model.dice.TcbInfoField;
import com.intel.bkp.verifier.model.evidence.MeasurementRecordHeader;
import com.intel.bkp.verifier.model.evidence.SectionType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.intel.bkp.verifier.model.dice.TcbInfoField.FWIDS;
import static com.intel.bkp.verifier.model.dice.TcbInfoField.INDEX;
import static com.intel.bkp.verifier.model.dice.TcbInfoField.LAYER;
import static com.intel.bkp.verifier.model.dice.TcbInfoField.TYPE;
import static com.intel.bkp.verifier.model.dice.TcbInfoField.VENDOR;
import static com.intel.bkp.verifier.model.dice.TcbInfoField.VENDOR_INFO;

class MeasurementRecordToTcbInfoMapperTest {

    private static final String EXPECTED_VENDOR = TcbInfoConstants.VENDOR;
    private static final String EXPECTED_TYPE_PREFIX = "2.16.840.1.113741.1.15.4.";
    private static final int EXPECTED_LAYER = 2;

    private final ByteBufferSafe buffer = ByteBufferSafe.wrap(new byte[100]);
    private final MeasurementRecordToTcbInfoMapper sut = new MeasurementRecordToTcbInfoMapper();

    private MeasurementRecordHeader header;

    @BeforeEach
    void setUp() {
        header = new MeasurementRecordHeader();
    }

    @Test
    void map_WithDeviceState() {
        // given
        header.setSectionType(SectionType.DEVICE_STATE);
        final var expectedKeys = List.of(VENDOR, TYPE, LAYER, VENDOR_INFO);
        final var notExpectedKeys = List.of(INDEX, FWIDS);

        // when
        final TcbInfo result = sut.map(header, buffer);

        // then
        verifyKeys(result, expectedKeys, notExpectedKeys);
    }

    @Test
    void map_WithPr() {
        // given
        header.setSectionType(SectionType.PR);
        final var expectedKeys = List.of(VENDOR, TYPE, LAYER, INDEX, FWIDS);
        final var notExpectedKeys = List.of(VENDOR_INFO);

        // when
        final TcbInfo result = sut.map(header, buffer);

        // then
        verifyKeys(result, expectedKeys, notExpectedKeys);
    }

    @Test
    void map_WithUserDesign() {
        // given
        header.setSectionType(SectionType.CORE);
        final var expectedKeys = List.of(VENDOR, TYPE, LAYER, FWIDS);
        final var notExpectedKeys = List.of(INDEX, VENDOR_INFO);

        // when
        final TcbInfo result = sut.map(header, buffer);

        // then
        verifyKeys(result, expectedKeys, notExpectedKeys);
    }

    private void verifyKeys(TcbInfo result, List<TcbInfoField> expectedKeys, List<TcbInfoField> notExpectedKeys) {
        final Map<TcbInfoField, Object> tcbInfo = result.getTcbInfo();
        Assertions.assertEquals(expectedKeys.size(), tcbInfo.size());
        Assertions.assertTrue(tcbInfo.keySet().containsAll(expectedKeys));
        Assertions.assertTrue(tcbInfo.keySet().stream().noneMatch(notExpectedKeys::contains));

        Assertions.assertEquals(EXPECTED_VENDOR, tcbInfo.get(VENDOR));
        Assertions.assertEquals(EXPECTED_TYPE_PREFIX + header.getSectionType().getValue(), tcbInfo.get(TYPE));
        Assertions.assertEquals(EXPECTED_LAYER, tcbInfo.get(LAYER));
    }
}
