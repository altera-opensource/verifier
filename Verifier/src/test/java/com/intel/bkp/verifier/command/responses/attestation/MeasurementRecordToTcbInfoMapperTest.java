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
import com.intel.bkp.verifier.model.dice.TcbInfoField;
import com.intel.bkp.verifier.model.evidence.MeasurementRecordHeader;
import com.intel.bkp.verifier.model.evidence.SectionType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

class MeasurementRecordToTcbInfoMapperTest {

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

        // when
        final TcbInfo result = sut.map(header, buffer);

        // then
        final Map<TcbInfoField, Object> tcbInfo = result.getTcbInfo();
        Assertions.assertEquals(4, tcbInfo.size());
        Assertions.assertTrue(tcbInfo.containsKey(TcbInfoField.VENDOR));
        Assertions.assertTrue(tcbInfo.containsKey(TcbInfoField.TYPE));
        Assertions.assertTrue(tcbInfo.containsKey(TcbInfoField.LAYER));
        Assertions.assertTrue(tcbInfo.containsKey(TcbInfoField.VENDOR_INFO));
        Assertions.assertFalse(tcbInfo.containsKey(TcbInfoField.INDEX));
        Assertions.assertFalse(tcbInfo.containsKey(TcbInfoField.FWIDS));
    }

    @Test
    void map_WithPr() {
        // given
        header.setSectionType(SectionType.PR);

        // when
        final TcbInfo result = sut.map(header, buffer);

        // then
        final Map<TcbInfoField, Object> tcbInfo = result.getTcbInfo();
        Assertions.assertEquals(5, tcbInfo.size());
        Assertions.assertTrue(tcbInfo.containsKey(TcbInfoField.VENDOR));
        Assertions.assertTrue(tcbInfo.containsKey(TcbInfoField.TYPE));
        Assertions.assertTrue(tcbInfo.containsKey(TcbInfoField.LAYER));
        Assertions.assertTrue(tcbInfo.containsKey(TcbInfoField.INDEX));
        Assertions.assertTrue(tcbInfo.containsKey(TcbInfoField.FWIDS));
        Assertions.assertFalse(tcbInfo.containsKey(TcbInfoField.VENDOR_INFO));
    }

    @Test
    void map_WithUserDesign() {
        // given
        header.setSectionType(SectionType.CORE);

        // when
        final TcbInfo result = sut.map(header, buffer);

        // then
        final Map<TcbInfoField, Object> tcbInfo = result.getTcbInfo();
        Assertions.assertEquals(4, tcbInfo.size());
        Assertions.assertTrue(tcbInfo.containsKey(TcbInfoField.VENDOR));
        Assertions.assertTrue(tcbInfo.containsKey(TcbInfoField.TYPE));
        Assertions.assertTrue(tcbInfo.containsKey(TcbInfoField.LAYER));
        Assertions.assertTrue(tcbInfo.containsKey(TcbInfoField.FWIDS));
        Assertions.assertFalse(tcbInfo.containsKey(TcbInfoField.VENDOR_INFO));
        Assertions.assertFalse(tcbInfo.containsKey(TcbInfoField.INDEX));
    }
}
