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

package com.intel.bkp.verifier.command.responses.attestation;

import com.intel.bkp.fpgacerts.dice.tcbinfo.FwidHashAlg;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoConstants;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.model.Oid;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.verifier.model.evidence.GpMeasurementRecordHeader;
import com.intel.bkp.verifier.model.evidence.GpMeasurementRecordHeaderBuilder;
import com.intel.bkp.verifier.model.evidence.SectionType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.FLAGS;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.FWIDS;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.INDEX;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.LAYER;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.MODEL;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.SVN;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.TYPE;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.VENDOR;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.VENDOR_INFO;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.VERSION;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GpMeasurementRecordToTcbInfoMapperTest {

    private static final String EXPECTED_VENDOR = TcbInfoConstants.VENDOR;
    private static final String EXPECTED_TYPE_PREFIX = Oid.MEASUREMENT_TYPES.getOid() + ".";
    private static final int EXPECTED_LAYER = 2;
    private static final int SECTION_INDEX = 5;

    private final ByteBufferSafe buffer = ByteBufferSafe.wrap(new byte[100]);
    private final GpMeasurementRecordToTcbInfoMapper sut = new GpMeasurementRecordToTcbInfoMapper();

    private GpMeasurementRecordHeader header;

    @BeforeEach
    void setUp() {
        header = new GpMeasurementRecordHeader();
        header.setSectionIndex(SECTION_INDEX);
    }

    @Test
    void map_WithDeviceState() {
        // given
        header.setSectionType((byte) SectionType.DEVICE_STATE.getValue());
        final var expectedKeys = List.of(VENDOR, TYPE, LAYER, VENDOR_INFO);
        final var notExpectedKeys = List.of(INDEX, FWIDS, SVN, VERSION, FLAGS);

        // when
        final Optional<TcbInfoMeasurement> result = sut.map(header, buffer);

        // then
        assertTrue(result.isPresent());
        verifyKeys(result.get(), expectedKeys, notExpectedKeys);
    }

    @Test
    void map_WithUserDesignPr() {
        // given
        header.setSectionType((byte) SectionType.PR.getValue());
        header.setMeasurementWithHeaderSize(getMeasurementSizeForUserDesign());
        final var expectedKeys = List.of(VENDOR, TYPE, LAYER, INDEX, FWIDS);
        final var notExpectedKeys = List.of(VENDOR_INFO, SVN, VERSION, FLAGS);

        // when
        final Optional<TcbInfoMeasurement> result = sut.map(header, buffer);

        // then
        assertTrue(result.isPresent());
        verifyKeys(result.get(), expectedKeys, notExpectedKeys);
    }

    @Test
    void map_WithUserDesign() {
        // given
        header.setSectionType((byte) SectionType.CORE.getValue());
        header.setMeasurementWithHeaderSize(getMeasurementSizeForUserDesign());
        final var expectedKeys = List.of(VENDOR, TYPE, LAYER, FWIDS);
        final var notExpectedKeys = List.of(INDEX, VENDOR_INFO, SVN, VERSION, FLAGS);

        // when
        final Optional<TcbInfoMeasurement> result = sut.map(header, buffer);

        // then
        assertTrue(result.isPresent());
        verifyKeys(result.get(), expectedKeys, notExpectedKeys);
    }

    @Test
    void map_WithUnsupportedSection_ReturnsEmpty() {
        // given
        final byte rawMeasurementSize = 10;
        final ByteBufferSafe buffer = ByteBufferSafe.wrap(new byte[rawMeasurementSize]);
        header.setSectionType((byte) 99);
        header.setMeasurementWithHeaderSize(getMeasurementSizeForUserDesign(rawMeasurementSize));

        // when
        final Optional<TcbInfoMeasurement> result = sut.map(header, buffer);

        // then
        assertTrue(result.isEmpty());
        assertEquals(0, buffer.remaining());
    }

    private static byte getMeasurementSizeForUserDesign() {
        return getMeasurementSizeForUserDesign((byte) FwidHashAlg.FWIDS_HASH_ALG_SHA384.getSize());
    }

    private static byte getMeasurementSizeForUserDesign(byte rawMeasurementSize) {
        return (byte) (rawMeasurementSize + GpMeasurementRecordHeaderBuilder.HEADER_SIZE);
    }

    private void verifyKeys(TcbInfoMeasurement result, List<TcbInfoField> expectedKeys,
                            List<TcbInfoField> notExpectedKeys) {

        final var actualKeys = getFieldsSetInMeasurement(result);
        expectedKeys.forEach(key -> assertTrue(actualKeys.contains(key)));
        notExpectedKeys.forEach(key -> Assertions.assertFalse(actualKeys.contains(key)));

        Assertions.assertEquals(EXPECTED_VENDOR, result.getKey().getVendor());
        Assertions.assertEquals(EXPECTED_TYPE_PREFIX + header.getSectionType(), result.getKey().getType());
        Assertions.assertEquals(EXPECTED_LAYER, result.getKey().getLayer());
    }

    private List<TcbInfoField> getFieldsSetInMeasurement(TcbInfoMeasurement measurement) {
        final var fields = new LinkedList<TcbInfoField>();

        final TcbInfoKey key = measurement.getKey();
        Optional.ofNullable(key.getVendor()).ifPresent(v -> fields.add(VENDOR));
        Optional.ofNullable(key.getModel()).ifPresent(v -> fields.add(MODEL));
        Optional.ofNullable(key.getType()).ifPresent(v -> fields.add(TYPE));
        Optional.ofNullable(key.getLayer()).ifPresent(v -> fields.add(LAYER));
        Optional.ofNullable(key.getIndex()).ifPresent(v -> fields.add(INDEX));

        final TcbInfoValue value = measurement.getValue();
        value.getVersion().ifPresent(v -> fields.add(VERSION));
        value.getSvn().ifPresent(v -> fields.add(SVN));
        value.getFwid().ifPresent(v -> fields.add(FWIDS));
        value.getFlags().ifPresent(v -> fields.add(FLAGS));
        value.getMaskedVendorInfo().ifPresent(v -> fields.add(VENDOR_INFO));

        return fields;
    }
}
